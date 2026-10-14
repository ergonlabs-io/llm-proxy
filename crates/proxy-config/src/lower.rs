//! Proto -> IR conversion ("lowering").
//!
//! Two passes over a loaded bootstrap:
//!
//! 1. **Surface check** (dynamic): walk every SET field reflectively and
//!    reject any field outside the supported surface with its full dotted
//!    path. This is AGENTS.md invariant 1's teeth — a field we have not implemented
//!    can never be silently ignored, and a proto upgrade that adds fields
//!    fails loudly instead of drifting.
//! 2. **Typed conversion**: build the [`crate::ir`] types from the typed
//!    protos, pre-computing matchers (S1 domain index, compiled regexes,
//!    weighted-cluster cumulative arrays) so the hot path never does it.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use prost_reflect::{DynamicMessage, ReflectMessage, Value};
use proxy_api::envoy::config::accesslog::v3 as accesslog_v3;
use proxy_api::envoy::config::bootstrap::v3::Bootstrap;
use proxy_api::envoy::config::cluster::v3 as cluster_v3;
use proxy_api::envoy::config::core::v3 as core_v3;
use proxy_api::envoy::config::endpoint::v3 as endpoint_v3;
use proxy_api::envoy::config::listener::v3 as listener_v3;
use proxy_api::envoy::config::route::v3 as route_v3;
use proxy_api::envoy::extensions::access_loggers::file::v3 as access_log_file_v3;
use proxy_api::envoy::extensions::access_loggers::stream::v3 as access_log_stream_v3;
use proxy_api::envoy::extensions::clusters::aggregate::v3 as aggregate_cluster_v3;
use proxy_api::envoy::extensions::filters::listener::tls_inspector::v3 as tls_inspector_v3;
use proxy_api::envoy::extensions::filters::network::http_connection_manager::v3 as hcm_v3;
use proxy_api::envoy::extensions::filters::network::tcp_proxy::v3 as tcp_proxy_v3;
use proxy_api::envoy::extensions::resource_monitors::downstream_connections::v3 as downstream_connections_v3;
use proxy_api::envoy::extensions::transport_sockets::tls::v3 as tls_v3;
use proxy_api::envoy::extensions::upstreams::http::v3 as upstream_http_v3;
use proxy_api::envoy::r#type::matcher::v3 as matcher_v3;
use proxy_api::envoy::r#type::v3 as type_v3;
use proxy_observability::access_log::{parse_format, FormatString};
// The trace exporter's own bound on a sane export deadline -- referenced here
// rather than restated so loader and exporter cannot drift (this crate already
// depends on `proxy-observability` for `FormatString`/`ResponseFlag` above).
use proxy_observability::otlp::TRACE_EXPORT_DEADLINE_MAX;
use proxy_observability::ResponseFlag;

use crate::error::ConfigError;
use crate::ir::*;
use crate::loader::LoadedBootstrap;

/// Build the immutable IR snapshot from a loaded bootstrap. This is the only
/// door between protobuf-land and the data plane (AGENTS.md invariant 2).
pub fn build_snapshot(loaded: &LoadedBootstrap) -> Result<ConfigSnapshot, ConfigError> {
    check_supported_surface(&loaded.dynamic, &mut String::new())?;

    let b: &Bootstrap = &loaded.bootstrap;
    let mut snapshot = ConfigSnapshot {
        version: SnapshotVersion(1),
        ..Default::default()
    };

    if let Some(admin) = &b.admin {
        let addr = admin
            .address
            .as_ref()
            .ok_or_else(|| invalid("admin", "admin requires an address"))?;
        let (host, port) = socket_host_port(addr, "admin.address")?;
        let ip: IpAddr = host
            .parse()
            .map_err(|_| invalid("admin.address", "admin address must be an IP address"))?;
        snapshot.admin = Some(SocketAddr::new(ip, port));
    }

    // See `convert_tracing_metadata`'s doc for why this
    // reads `node.metadata` rather than a `static_resources`-adjacent field.
    snapshot.tracing = convert_tracing_metadata(b.node.as_ref(), "node")?;
    // Deliberately a SEPARATE namespace key and a separate IR field from the
    // `tracing` block above, not a mode of it: `docs/telemetry-design.md` §5.3
    // requires metric export to be configurable with tracing off, and a shared
    // block could not express that without a flag whose false value would still
    // require the operator to write the tracing namespace at all.
    snapshot.metrics = convert_metrics_metadata(b.node.as_ref(), "node")?;
    snapshot.end_user_capture_configured = b
        .node
        .as_ref()
        .and_then(|n| n.metadata.as_ref())
        .is_some_and(|m| m.fields.contains_key("io.llmproxy.capture"));
    #[cfg(unix)]
    {
        snapshot.end_user_capture = crate::capture::convert(b.node.as_ref())?;
    }
    #[cfg(not(unix))]
    if b.node
        .as_ref()
        .and_then(|node| node.metadata.as_ref())
        .is_some_and(|metadata| metadata.fields.contains_key("io.llmproxy.capture"))
    {
        return Err(unsupported(
            "node.metadata[\"io.llmproxy.capture\"]",
            "declarative capture policy is not implemented; use the boot-only metadata-agent CLI",
        ));
    }

    snapshot.max_downstream_connections =
        convert_overload_manager(b.overload_manager.as_ref(), "overload_manager")?;

    // Lowered before `static_resources` so the ADS
    // cluster-existence check below can run against the finished cluster map.
    let ads_pending = convert_dynamic_resources(b, "dynamic_resources")?;

    let Some(sr) = &b.static_resources else {
        // An ADS config naming a cluster is only legal with static resources
        // to declare that cluster in -- catch it here rather than letting the
        // early return skip the existence check.
        if let Some(ads) = &ads_pending {
            return Err(invalid(
                "dynamic_resources.ads_config.grpc_services[0].envoy_grpc.cluster_name",
                format!(
                    "ADS cluster `{}` must be statically defined, but this bootstrap has no static_resources",
                    ads.cluster.as_deref().unwrap_or("<filesystem>")
                ),
            ));
        }
        return Ok(snapshot);
    };

    // `seen_stat_prefixes` accumulates across EVERY listener in
    // this bootstrap, not just within one -- two listeners each configuring
    // `llmproxy.auth` with the same `stat_prefix` is exactly the ambiguity
    // this check exists to reject. See `check_admin_addressable_stat_prefixes`'s
    // doc for why only `llmproxy.auth`-configuring chains are covered.
    let mut seen_stat_prefixes: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for (i, l) in sr.listeners.iter().enumerate() {
        let path = format!("static_resources.listeners[{i}]");
        let ir = convert_listener(l, &path)?;
        check_admin_addressable_stat_prefixes(&ir, &path, &mut seen_stat_prefixes)?;
        if snapshot
            .listeners
            .insert(ir.name.clone(), Arc::new(ir))
            .is_some()
        {
            return Err(invalid(
                &path,
                format!("duplicate listener name `{}`", l.name),
            ));
        }
    }
    for (i, c) in sr.clusters.iter().enumerate() {
        let path = format!("static_resources.clusters[{i}]");
        let ir = convert_cluster(c, &path)?;
        if snapshot
            .clusters
            .insert(ir.name.clone(), Arc::new(ir))
            .is_some()
        {
            return Err(invalid(
                &path,
                format!("duplicate cluster name `{}`", c.name),
            ));
        }
    }
    // Aggregate members refer to other clusters by
    // name, so they can only be checked once the whole map exists -- this
    // cannot fold into the loop above, because a member may be declared
    // after the aggregate that names it.
    validate_cluster_graph(sr, &snapshot)?;

    // The proto is explicit -- "The cluster with name `cluster_name`
    // must be statically defined". Checked here, once the cluster map is
    // complete, for the same reason `validate_cluster_graph` is.
    if let Some(ads) = &ads_pending {
        if let Some(cluster) = &ads.cluster {
            if !snapshot.clusters.contains_key(cluster) {
                return Err(invalid(
                    "dynamic_resources.ads_config.grpc_services[0].envoy_grpc.cluster_name",
                    format!(
                        "ADS cluster `{}` is not defined in static_resources.clusters",
                        cluster.as_str()
                    ),
                ));
            }
        }
    }
    validate_ext_authz_clusters(&mut snapshot)?;
    snapshot.ads = ads_pending;
    Ok(snapshot)
}

// --------------------------------------------------- single xDS resource lowering --

/// Full proto type name a dynamic `Cluster` resource must carry.
const DYNAMIC_CLUSTER_TYPE: &str = "envoy.config.cluster.v3.Cluster";
/// Full proto type name a dynamic `Listener` resource must carry.
const DYNAMIC_LISTENER_TYPE: &str = "envoy.config.listener.v3.Listener";
/// Full proto type name a dynamic RDS resource must carry.
const DYNAMIC_ROUTE_TYPE: &str = "envoy.config.route.v3.RouteConfiguration";
/// Full proto type name a dynamic `ClusterLoadAssignment` (EDS) resource must
/// carry.
const DYNAMIC_ENDPOINTS_TYPE: &str = "envoy.config.endpoint.v3.ClusterLoadAssignment";

/// Lower one xDS-delivered resource `Any` into its typed proto `T`, running
/// the SAME strict-mode surface check `build_snapshot` runs over a whole
/// file-loaded bootstrap (AGENTS.md invariant 1) -- just scoped to this one
/// resource instead of the whole tree. `path` is the caller's dotted-path
/// root (e.g. `cds.clusters[payments-primary]`); every error below, and every
/// error the surface walk finds deeper inside this resource, is reported
/// rooted at it. `expected_type` is the full proto type name this resource
/// must carry (e.g. `envoy.config.cluster.v3.Cluster`).
///
/// Rust note: `T: prost::Message + Default` is the same bound
/// [`decode_any`] uses -- any generated prost message type can be decoded
/// this way, so this one function serves both [`lower_dynamic_cluster`] and
/// [`lower_dynamic_listener`] without repeating the type-URL/pool/surface-walk
/// plumbing in each.
fn lower_dynamic_any<T: prost::Message + Default>(
    any: &prost_types::Any,
    path: &str,
    expected_type: &str,
) -> Result<T, ConfigError> {
    // The pool lookup runs first, keyed by whatever type name actually
    // arrived: a type absent from the pool entirely (garbage, or a real Envoy
    // type we simply haven't vendored) is `UnknownTypeUrl`, distinct from a
    // real, resolvable type that just isn't the one this call expects.
    let actual_type = type_name(any);
    let inner_desc = proxy_api::descriptor_pool()
        .get_message_by_name(actual_type)
        .ok_or_else(|| ConfigError::UnknownTypeUrl {
            field_path: path.to_string(),
            type_url: any.type_url.clone(),
        })?;
    if actual_type != expected_type {
        return Err(invalid(
            path,
            format!("expected `{expected_type}`, found `{actual_type}`"),
        ));
    }

    let dyn_msg = DynamicMessage::decode(inner_desc, any.value.as_slice())
        .map_err(|e| ConfigError::Parse(format!("cannot decode `{}`: {e}", any.type_url)))?;
    // Rust note: `check_supported_surface` mutates this buffer as it recurses
    // (push a field name, recurse, truncate back) -- seeding it with `path`
    // instead of starting from `String::new()` is what makes a nested
    // unsupported-field error read `<path>.<field>...` rather than restarting
    // from the resource root's own name.
    let mut walk_path = path.to_string();
    check_supported_surface(&dyn_msg, &mut walk_path)?;

    decode_any::<T>(any, path)
}

/// Lower one xDS-delivered `Cluster` resource into IR.
///
/// `path` is the caller-supplied dotted-path root for every error raised
/// beneath it -- the ADS client passes something like
/// `cds.clusters[payments-primary]`, mirroring how [`build_snapshot`] passes
/// `static_resources.clusters[{i}]` for a file-loaded one. This runs the same
/// strict-mode surface check `build_snapshot` applies to file config (AGENTS.md
/// invariant 1) over this one resource before converting anything, so an
/// xDS-delivered `Cluster` cannot carry a field the file loader would reject
/// and slip through just because it arrived over the wire instead.
pub fn lower_dynamic_cluster(
    any: &prost_types::Any,
    path: &str,
) -> Result<ClusterConfig, ConfigError> {
    let c: cluster_v3::Cluster = lower_dynamic_any(any, path, DYNAMIC_CLUSTER_TYPE)?;
    convert_cluster(&c, path)
}

/// Lower one xDS-delivered `Listener` resource into IR. See
/// [`lower_dynamic_cluster`] for what `path` roots and why the surface check
/// runs here too -- xDS is not a hole around strict mode.
pub fn lower_dynamic_listener(
    any: &prost_types::Any,
    path: &str,
) -> Result<ListenerConfig, ConfigError> {
    let l: listener_v3::Listener = lower_dynamic_any(any, path, DYNAMIC_LISTENER_TYPE)?;
    let listener = convert_listener(&l, path)?;
    for chain in listener
        .filter_chains
        .iter()
        .chain(listener.default_filter_chain.iter())
    {
        for network in &chain.filters {
            if let NetworkFilterSpec::HttpConnectionManager(hcm) = network {
                if let Some(cfg) = hcm.http_filters.iter().find_map(|f| f.ext_authz.as_ref()) {
                    return Err(unsupported(&cfg.field_path, "ext_authz is bootstrap-only until authorization cluster warming is implemented"));
                }
            }
        }
    }
    Ok(listener)
}

/// Lower one ADS-delivered RDS resource. Like CDS/LDS lowering, this uses the
/// same surface walk as file configuration so RDS is never a strict-mode hole.
pub fn lower_dynamic_route(any: &prost_types::Any, path: &str) -> Result<RouteTable, ConfigError> {
    let route: route_v3::RouteConfiguration = lower_dynamic_any(any, path, DYNAMIC_ROUTE_TYPE)?;
    convert_route_table(&route, path)
}

/// Lower one xDS-delivered `ClusterLoadAssignment` (an EDS resource) into its
/// endpoints. See [`lower_dynamic_cluster`] for what `path` roots and why the
/// surface check runs here too -- an EDS response is not exempt from AGENTS.md
/// invariant 1 just because it never touches a bootstrap file.
///
/// Returns the assignment's `cluster_name` alongside the endpoints. That
/// field is the EDS **resource name** -- it is what an `EdsClusterConfig`
/// subscribes to via `service_name`, not necessarily the
/// `Cluster.name` the endpoints end up attached to (Envoy allows the two to
/// differ so several `Cluster`s can share one EDS resource). The caller
/// is what matches this name back to a pending
/// subscription; nothing here assumes a 1:1 mapping.
pub fn lower_dynamic_endpoints(
    any: &prost_types::Any,
    path: &str,
) -> Result<(String, Vec<EndpointIR>), ConfigError> {
    let la: endpoint_v3::ClusterLoadAssignment =
        lower_dynamic_any(any, path, DYNAMIC_ENDPOINTS_TYPE)?;

    let mut endpoints = Vec::new();
    for (i, locality) in la.endpoints.iter().enumerate() {
        let priority = locality.priority;
        for (j, lbe) in locality.lb_endpoints.iter().enumerate() {
            let e_path = format!("{path}.endpoints[{i}].lb_endpoints[{j}]");
            // `convert_endpoint` takes a `DiscoveryType` to decide whether
            // a literal IP is required. It is for `Eds`, and the reason is
            // downstream of here: these endpoints are installed by
            // `ClusterManager::accept_eds_update` through
            // `discovery::static_hosts`, which does no name resolution.
            // Envoy's EDS wire format permits a hostname -- we cannot use
            // one -- so refusing it here keeps the failure a config-time
            // error carrying a dotted path rather than an `io::Error` on
            // every push. See `convert_endpoint` for the wording.
            endpoints.push(convert_endpoint(
                lbe,
                priority,
                DiscoveryType::Eds,
                &e_path,
            )?);
        }
    }
    Ok((la.cluster_name, endpoints))
}

// ------------------------------------------------------------ surface check --

/// Fields we currently map to IR, per message type. A message type absent from
/// this table is either a leaf we map wholesale or is only reachable through
/// checked parents; a listed type rejects every set field not named.
fn allowed_fields(message: &str) -> Option<&'static [&'static str]> {
    Some(match message {
        "envoy.config.bootstrap.v3.Bootstrap" => {
            &[
                "node",
                "admin",
                "static_resources",
                "dynamic_resources",
                // Only the global downstream connection cap is lowered; see
                // `convert_overload_manager`.
                "overload_manager",
            ]
        }
        // Everything else (`refresh_interval`, `actions`, `loadshed_points`,
        // `buffer_factory_config`) is refused by this allow-list.
        "envoy.config.overload.v3.OverloadManager" => &["resource_monitors"],
        "envoy.config.overload.v3.ResourceMonitor" => &["name", "typed_config"],
        "envoy.config.bootstrap.v3.Bootstrap.DynamicResources" => {
            &["lds_config", "cds_config", "ads_config"]
        }
        "envoy.config.core.v3.ApiConfigSource" => {
            &["api_type", "transport_api_version", "grpc_services"]
        }
        "envoy.config.core.v3.GrpcService" => &["envoy_grpc", "timeout"],
        "envoy.config.core.v3.GrpcService.EnvoyGrpc" => &["cluster_name"],
        "envoy.config.bootstrap.v3.Admin" => &["address"],
        "envoy.config.bootstrap.v3.Bootstrap.StaticResources" => &["listeners", "clusters"],
        "envoy.config.listener.v3.Listener" => &[
            "name",
            "address",
            "filter_chains",
            "default_filter_chain",
            "listener_filters",
            "per_connection_buffer_limit_bytes",
            "tcp_backlog_size",
            "bind_to_port",
            "ignore_global_conn_limit",
        ],
        "envoy.config.listener.v3.ListenerFilter" => &["name", "typed_config"],
        "envoy.config.listener.v3.FilterChain" => {
            &[
            "name",
            "filter_chain_match",
            "filters",
            "transport_socket",
            "transport_socket_connect_timeout",
        ]
        }
        "envoy.config.listener.v3.FilterChainMatch" => &[
            "destination_port",
            "prefix_ranges",
            "server_names",
            "transport_protocol",
            "application_protocols",
            "direct_source_prefix_ranges",
            "source_type",
            "source_prefix_ranges",
            "source_ports",
        ],
        "envoy.config.listener.v3.Filter" => &["name", "typed_config"],
        "envoy.config.core.v3.Address" => &["socket_address"],
        "envoy.config.core.v3.CidrRange" => &["address_prefix", "prefix_len"],
        "envoy.config.core.v3.SocketAddress" => &["address", "port_value", "protocol"],
        "envoy.config.core.v3.TransportSocket" => &["name", "typed_config"],
        "envoy.config.core.v3.DataSource" => &["filename", "inline_string"],
        "envoy.config.core.v3.HeaderValueOption" => &["header", "append_action"],
        "envoy.config.core.v3.HeaderValue" => &["key", "value"],
        "envoy.config.cluster.v3.Cluster" => &[
            "name",
            "type",
            "cluster_type",
            "connect_timeout",
            "lb_policy",
            "load_assignment",
            "transport_socket",
            "per_connection_buffer_limit_bytes",
            "circuit_breakers",
            "typed_extension_protocol_options",
            "metadata",
            "health_checks",
            "outlier_detection",
            // EDS clusters -- see `convert_eds_cluster_config`.
            "eds_cluster_config",
            // STRICT_DNS / LOGICAL_DNS re-resolution timing -- see
            // `convert_dns_refresh`. The resolver itself is not
            // configurable: `dns_lookup_family`, `dns_resolvers`,
            // `use_tcp_for_dns_lookups`, `dns_resolution_config` and
            // `typed_dns_resolver_config` stay off this list on purpose, so
            // setting one fails loudly instead of being ignored.
            "dns_refresh_rate",
            "dns_jitter",
            "dns_failure_refresh_rate",
            // Listed only so `convert_dns_refresh` can reject `true` with an
            // explanation; the generic "not implemented yet" text would not
            // say why.
            "respect_dns_ttl",
        ],
        // The `dns_failure_refresh_rate` message. Both fields are mapped by
        // `convert_dns_refresh`; the entry is here so a field a later Envoy
        // adds to the message is rejected instead of skipped (an absent entry
        // makes the surface walk accept everything, see the two entries
        // below).
        "envoy.config.cluster.v3.Cluster.RefreshRate" => &["base_interval", "max_interval"],
        // The only custom cluster type implemented is
        // `envoy.clusters.aggregate` (see `convert_cluster`'s
        // `ClusterDiscoveryType::ClusterType` arm).
        //
        // Both entries are forward-compat insurance, and NO test can exercise
        // either one today -- each message's full field set is already mapped,
        // so there is no real-but-unlisted field a config could set. Do not
        // delete them as dead weight: `allowed_fields` returning `None` skips
        // the field-name check entirely (see `check_supported_surface`), so
        // the day an Envoy proto bump adds a field to either message, its
        // absence here is a silent no-op -- AGENTS.md invariant 1's exact failure
        // mode, arriving with no code change of ours to blame it on.
        "envoy.config.cluster.v3.Cluster.CustomClusterType" => &["name", "typed_config"],
        "envoy.extensions.clusters.aggregate.v3.ClusterConfig" => &["clusters"],
        // `service_name` maps to IR (with its
        // default-to-cluster-name behavior); `eds_config` is walked below via
        // `check_ads_source`'s ADS-only reasoning (see
        // `convert_eds_cluster_config`). `envoy.config.core.v3.ConfigSource`
        // itself is deliberately absent from this table -- same as
        // `dynamic_resources`'s `ads_config`/`lds_config`/`cds_config`
        // above it, its per-specifier rejection happens in typed code, not
        // the surface walk, so the surface walk lets every one of its fields
        // through and `check_ads_source` is what actually rejects the
        // unimplemented ones by name.
        "envoy.config.cluster.v3.Cluster.EdsClusterConfig" => &["eds_config", "service_name"],
        // The first proto this project defines
        // itself rather than borrowing from Envoy. Listed for the same
        // forward-compat reason as the two entries above -- every field is
        // mapped today, so no config can trip these -- but with one difference
        // that makes them likelier to matter: WE add the fields to this
        // message. An `llmproxy.filters.v0` field added without a matching
        // entry here would be accepted and ignored, which is AGENTS.md invariant 1's
        // exact failure mode arriving from our own change rather than an Envoy
        // bump.
        // `store` is a `oneof` -- its members (`in_memory`,
        // `persistent`) appear here under their OWN field names, not under
        // the oneof's Rust-level name ("store"), because that is how
        // `check_supported_surface` walks a `oneof` (it sees whichever
        // variant is actually set, by that variant's field name). Before
        // this fix, both were absent, so any config that set `persistent`
        // was rejected by this surface walk with `UnsupportedField` --
        // making the redb-backed store unreachable through Envoy-mode config
        // even though `auth_filter::parse_store` fully supported it. The
        // NEXT `store` variant added must be listed here too, or it repeats
        // this exact bug.
        "llmproxy.filters.v0.Authentication" => &[
            "hmac_secret",
            "virtual_keys",
            "in_memory",
            "persistent",
            "shared",
            "poll_interval_seconds",
            "jwt_providers",
            "tenant_credentials",
        ],
        "llmproxy.filters.v0.TenantCredentials" => {
            &["encryption_key_file", "encryption_key_id", "previous_keys"]
        }
        "llmproxy.filters.v0.PreviousCredentialKey" => &["id", "file"],
        "llmproxy.filters.v0.VirtualKey" => &["key_id", "tenant", "digest_hex", "revoked"],
        "llmproxy.filters.v0.JwtProvider" => &[
            "tenant_claim",
            "issuer",
            "audience",
            "keys",
            "tenant_values",
            "discovery_url",
            "refresh_interval_seconds",
            "trusted_ca",
            "subject_claim",
        ],
        "llmproxy.filters.v0.JwtKey" => &["kid", "n", "e"],
        // The owned token-budget shape.  Keep both fields
        // here even though the factory performs the required/value checks:
        // this is the forward-compat guard that rejects a future proto field
        // until a reader is deliberately added.
        "llmproxy.filters.v0.SpendLimit" => &[
            "pricing",
            "default_period",
            "flush_interval_seconds",
            "reconciliation_bound_seconds",
            "on_reconciliation_expired",
            "recovery_journal_path",
            "legacy_tenant_budget_cutover",
        ],
        "llmproxy.filters.v0.ClusterPricing" => &["cluster", "models"],
        "llmproxy.filters.v0.ModelPrice" => &[
            "model",
            "input_per_million",
            "output_per_million",
            "cached_per_million",
            "cache_creation_per_million",
        ],
        "llmproxy.filters.v0.TokenLimit" => &["max_tokens", "fill_rate"],
        // One-release compatibility for the old borrowed token-limit type.
        // RateLimitSettings has unrelated xDS fields; accepting any of them
        // would claim the limiter honors a knob it never reads.
        "envoy.config.core.v3.RateLimitSettings" => &["max_tokens", "fill_rate"],
        // Owned usage-filter configuration. The pricing
        // payload is intentionally opaque JSON; usage_filter validates its
        // schema before building the listener factory.
        "llmproxy.filters.v0.Usage" => &["dialect", "pricing_json"],
        // Owned body-rewrite configuration.
        "llmproxy.filters.v0.BodyRewrite" => &["enabled", "dialect"],
        // Model resolution. Listed so a future resolver branch is a strict-mode
        // error until a reader is deliberately added.
        "llmproxy.filters.v0.ModelResolver" => &["rules"],
        "llmproxy.filters.v0.StaticModelRules" => &["default_model", "tenants"],
        "llmproxy.filters.v0.TenantModelRule" => &["tenant", "model"],
        // One-release compatibility for the old borrowed body-rewrite type.
        "envoy.config.core.v3.RuntimeFeatureFlag" => &["default_value", "runtime_key"],
        // The Redis-backed shared store. `url` is an
        // `envoy.config.core.v3.DataSource`, already listed above under its
        // own entry -- same reasoning as `hmac_secret`.
        "llmproxy.filters.v0.SharedStore" => &["url", "namespace"],
        // Only the `io.llmproxy.provider_auth` namespace under
        // `filter_metadata` is understood -- see
        // `convert_provider_auth_metadata`. `typed_filter_metadata` is not
        // implemented and stays out of this list so setting it is a strict-
        // mode error rather than a silent no-op (AGENTS.md invariant 1); Envoy
        // itself only consults it when the plain map is absent, so no config
        // that already works today needs it.
        "envoy.config.core.v3.Metadata" => &["filter_metadata"],
        // S5 circuit breakers. `per_host_thresholds` is deliberately excluded
        // (we don't model per-host limits); a config setting it is rejected
        // by the surface walk with its dotted path (AGENTS.md invariant 1) rather
        // than silently ignored.
        "envoy.config.cluster.v3.CircuitBreakers" => &["thresholds"],
        // `track_remaining` and `max_connection_pools` stay out on purpose:
        // this build has neither their stats surface nor per-cluster pool
        // cap. `retry_budget` is different: it is lowered and enforced.
        "envoy.config.cluster.v3.CircuitBreakers.Thresholds" => &[
            "priority",
            "max_connections",
            "max_pending_requests",
            "max_requests",
            "max_retries",
            "retry_budget",
        ],
        "envoy.config.cluster.v3.CircuitBreakers.Thresholds.RetryBudget" => &[
            "budget_percent",
            "min_retry_concurrency",
        ],
        // S6 active health checking. `initial_jitter`,
        // `interval_jitter_percent`, `alt_port`, `reuse_connection`,
        // `unhealthy_interval`/`unhealthy_edge_interval`/`healthy_edge_interval`,
        // `event_log_path`, `event_logger`, `event_service`,
        // `always_log_health_check_*`, `tls_options`, and
        // `transport_socket_match_criteria` are not implemented and stay off
        // this list on purpose -- setting any of them must fail loudly.
        // `grpc_health_check` and `custom_health_check` ARE listed here even
        // though neither reaches the IR: `convert_health_check` rejects both
        // explicitly with an operator-facing message (a stub that always
        // reports healthy is worse than refusing the config), and that only
        // fires if the surface walk lets the field through instead of
        // stopping on its own generic "not implemented yet" text first --
        // same reasoning as `LbPolicy::RingHash`/`Maglev` in `convert_cluster`.
        "envoy.config.core.v3.HealthCheck" => &[
            "timeout",
            "interval",
            "interval_jitter",
            "unhealthy_threshold",
            "healthy_threshold",
            "no_traffic_interval",
            "http_health_check",
            "tcp_health_check",
            "grpc_health_check",
            "custom_health_check",
        ],
        // `send`, `receive`, `response_buffer_size`, `request_headers_to_add`,
        // `request_headers_to_remove`, `retriable_statuses`,
        // `codec_client_type`, `service_name_matcher`, and `method` are not
        // implemented -- no HTTP-body payload matching, no header injection,
        // no retriable-status bucket, always GET/1.1.
        "envoy.config.core.v3.HealthCheck.HttpHealthCheck" => {
            &["host", "path", "expected_statuses"]
        }
        // `proxy_protocol_config` is not implemented.
        "envoy.config.core.v3.HealthCheck.TcpHealthCheck" => &["send", "receive"],
        "envoy.config.core.v3.HealthCheck.Payload" => &["text", "binary"],
        "envoy.type.v3.Int64Range" => &["start", "end"],
        // S6 passive outlier detection. The local-origin split
        // (`consecutive_local_origin_failure`,
        // `enforcing_consecutive_local_origin_failure`,
        // `enforcing_local_origin_success_rate`,
        // `enforcing_failure_percentage_local_origin`), `max_ejection_time_jitter`,
        // `monitors`, and `detect_degraded_hosts` are not implemented and stay
        // off this list on purpose -- setting any of them must fail loudly.
        // `split_external_local_origin_errors` IS listed even though only its
        // `false` value is honored: `convert_outlier_detection` rejects `true`
        // with an operator-facing message, and that only fires if the surface
        // walk lets the field through first -- same pattern as
        // `grpc_health_check` above.
        "envoy.config.cluster.v3.OutlierDetection" => &[
            "consecutive_5xx",
            "interval",
            "base_ejection_time",
            "max_ejection_time",
            "max_ejection_percent",
            "always_eject_one_host",
            "enforcing_consecutive_5xx",
            "consecutive_gateway_failure",
            "enforcing_consecutive_gateway_failure",
            "success_rate_minimum_hosts",
            "success_rate_request_volume",
            "success_rate_stdev_factor",
            "enforcing_success_rate",
            "failure_percentage_threshold",
            "enforcing_failure_percentage",
            "failure_percentage_minimum_hosts",
            "failure_percentage_request_volume",
            "split_external_local_origin_errors",
            "successful_active_health_check_uneject_host",
        ],
        "envoy.config.endpoint.v3.ClusterLoadAssignment" => &["cluster_name", "endpoints"],
        "envoy.config.endpoint.v3.LocalityLbEndpoints" => &["lb_endpoints", "priority"],
        // `metadata` lowers into `EndpointIR::metadata` -- see
        // `convert_endpoint_metadata`. `health_status` stays off this list;
        // nothing consumes EDS-reported health today, so a config setting it
        // must fail loudly rather than have the value silently dropped.
        "envoy.config.endpoint.v3.LbEndpoint" => &["endpoint", "load_balancing_weight", "metadata"],
        "envoy.config.endpoint.v3.Endpoint" => &["address"],
        "envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy" => &[
            "stat_prefix",
            "cluster",
            "idle_timeout",
            "max_connect_attempts",
        ],
        "envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager" => &[
            "codec_type",
            "stat_prefix",
            "route_config",
            "rds",
            "http_filters",
            "generate_request_id",
            "use_remote_address",
            "xff_num_trusted_hops",
            "access_log",
            // Downstream admission deadlines; see `convert_hcm`.
            "request_headers_timeout",
            "request_timeout",
            // Stream-lifetime bounds; see `convert_hcm`.
            "stream_idle_timeout",
            "common_http_protocol_options",
            // Listed so a config setting it gets
            // `convert_hcm`'s specific "not implemented, see the dialect"
            // message instead of the generic surface-check one -- see
            // `HttpConnectionManager.Tracing`'s entry just below for why the
            // rejection happens there rather than mapping anything.
            "tracing",
            // S10: the upgrade types this HCM will tunnel. Lowered by
            // `convert_hcm` into `HttpConnectionManagerConfig::upgrade_configs`.
            "upgrade_configs",
        ],
        // RDS has the same ADS-only ConfigSource rule as EDS/SDS. The typed
        // converter performs its per-specifier refusal so all members pass
        // through this surface layer first.
        // Only the stream lifetime is mapped. The connection-level fields on
        // this message (`idle_timeout`, `max_connection_duration`, ...) stay
        // rejected by the surface walk until something reads them.
        "envoy.config.core.v3.HttpProtocolOptions" => &["max_stream_duration"],
        "envoy.extensions.filters.network.http_connection_manager.v3.Rds" => {
            &["config_source", "route_config_name"]
        }
        // S10: `filters` is deliberately NOT listed -- per-upgrade
        // filter chains are unimplemented (the tunnel is transparent, S10.2
        // deferred), so a config setting them is rejected right here by the
        // surface walk with the generic "not implemented yet" message rather
        // than needing a convert-time check. `upgrade_type`/`enabled` are the
        // supported surface.
        "envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager.UpgradeConfig" => {
            &["upgrade_type", "enabled"]
        }
        // `tracing`'s own message: `&[]` (nothing mapped, same shape as the
        // Router filter's own entry above) because `envoy.config.trace.v3.
        // OpenTelemetryConfig` -- the tracer extension the real `provider`
        // field would point `typed_config` at -- is not compiled into the
        // descriptor pool (`proxy-api/build.rs`'s `roots` doesn't list
        // `envoy/config/trace/v3/opentelemetry.proto`, and nothing else pulls
        // it in transitively; confirmed by querying `descriptor_pool()`
        // directly). Vendoring it without a real mapping behind it would just
        // move the failure from a clean `unsupported()` here to an opaque
        // `UnknownTypeUrl` two layers deeper, so `convert_hcm` rejects the
        // whole `tracing` block outright instead -- see its comment. The
        // `llmproxy` dialect's `observability.tracing` is the supported
        // surface for now; it builds `TracingConfig` directly rather than
        // through this proto (see `convert_tracing_metadata` below).
        "envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager.Tracing" => &[],
        "envoy.extensions.filters.network.http_connection_manager.v3.HttpFilter" => {
            &["name", "typed_config"]
        }
        "envoy.extensions.filters.http.router.v3.Router" => &[],
        "envoy.extensions.filters.http.ext_authz.v3.ExtAuthz" => &[
            "grpc_service", "transport_api_version", "failure_mode_allow",
            "failure_mode_allow_header_add", "status_on_error", "clear_route_cache",
            "stat_prefix", "encode_raw_headers", "validate_mutations",
            "enable_dynamic_metadata_ingestion", "charge_cluster_response_stats",
        ],
        "envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute" => &["disabled", "check_settings"],
        "envoy.extensions.filters.http.ext_authz.v3.CheckSettings" => &["context_extensions"],
        // Access logging.
        "envoy.config.accesslog.v3.AccessLog" => &["name", "filter", "typed_config"],
        "envoy.config.accesslog.v3.AccessLogFilter" => {
            &["status_code_filter", "response_flag_filter"]
        }
        "envoy.config.accesslog.v3.StatusCodeFilter" => &["comparison"],
        "envoy.config.accesslog.v3.ComparisonFilter" => &["op", "value"],
        "envoy.config.core.v3.RuntimeUInt32" => &["default_value", "runtime_key"],
        "envoy.config.accesslog.v3.ResponseFlagFilter" => &["flags"],
        "envoy.extensions.access_loggers.file.v3.FileAccessLog" => &["path", "log_format"],
        "envoy.extensions.access_loggers.stream.v3.StdoutAccessLog" => &["log_format"],
        "envoy.extensions.access_loggers.stream.v3.StderrAccessLog" => &["log_format"],
        // `formatters`, `json_format_options`, `content_type`, and
        // `omit_empty_values` are not implemented (no custom formatter
        // plugins, no JSON-key-omission knob, no content-type override, and
        // absent values always render `-` regardless of this flag); leaving
        // them out of this list means setting any of them is a strict-mode
        // error rather than a silent behavior change.
        "envoy.config.core.v3.SubstitutionFormatString" => &["text_format", "json_format"],
        "envoy.config.route.v3.RouteConfiguration" => {
            &["name", "virtual_hosts", "typed_per_filter_config"]
        }
        "envoy.config.route.v3.VirtualHost" => &[
            "name",
            "domains",
            "routes",
            "typed_per_filter_config",
            "include_request_attempt_count",
            "include_attempt_count_in_response",
        ],
        "envoy.config.route.v3.Route" => &[
            "name",
            "match",
            "route",
            "redirect",
            "direct_response",
            "metadata",
            "request_headers_to_add",
            "typed_per_filter_config",
        ],
        // ADR-0004 step 4: the `Any` wrapper Envoy allows around a per-route
        // filter override, carrying `is_optional`/`disabled` alongside the
        // inner config. See `convert_typed_per_filter_config`.
        "envoy.config.route.v3.FilterConfig" => &["config", "is_optional", "disabled"],
        "envoy.config.route.v3.RouteMatch" => {
            &["prefix", "path", "safe_regex", "case_sensitive", "headers"]
        }
        "envoy.config.route.v3.HeaderMatcher" => &["name", "string_match", "present_match"],
        "envoy.type.matcher.v3.StringMatcher" => &[
            "exact",
            "prefix",
            "suffix",
            "contains",
            "safe_regex",
            "ignore_case",
        ],
        "envoy.type.matcher.v3.RegexMatcher" => &["regex", "google_re2"],
        "envoy.config.route.v3.RouteAction" => &[
            "cluster",
            "cluster_header",
            "weighted_clusters",
            "timeout",
            "idle_timeout",
            "retry_policy",
            "hedge_policy",
            "host_rewrite_literal",
            "prefix_rewrite",
        ],
        "envoy.config.route.v3.WeightedCluster" => &["clusters"],
        "envoy.config.route.v3.WeightedCluster.ClusterWeight" => &["name", "weight"],
        "envoy.config.route.v3.RetryPolicy" => &[
            "retry_on",
            "num_retries",
            "per_try_timeout",
            "retriable_status_codes",
            "retry_back_off",
            "host_selection_retry_max_attempts",
            "retry_host_predicate",
        ],
        "envoy.config.route.v3.RetryPolicy.RetryHostPredicate" => &["name", "typed_config"],
        "envoy.config.route.v3.RetryPolicy.RetryBackOff" => &["base_interval", "max_interval"],
        "envoy.config.route.v3.HedgePolicy" => &[
            "initial_requests",
            "additional_request_chance",
            "hedge_on_per_try_timeout",
        ],
        "envoy.config.route.v3.RedirectAction" => &[
            "host_redirect",
            "path_redirect",
            "https_redirect",
            "response_code",
        ],
        "envoy.config.route.v3.DirectResponseAction" => &["status", "body"],
        "envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext" => {
            &["sni", "common_tls_context"]
        }
        "envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext" => &[
            "common_tls_context",
            "require_client_certificate",
            "disable_stateless_session_resumption",
        ],
        "envoy.extensions.transport_sockets.tls.v3.CommonTlsContext" => &[
            "tls_params",
            "tls_certificates",
            "tls_certificate_sds_secret_configs",
            "validation_context",
            "validation_context_sds_secret_config",
            "alpn_protocols",
        ],
        // Listed even though its only two fields (`name`, `sds_config`) are
        // both already handled explicitly -- a future proto bump that adds a
        // third field should fail loudly here rather than pass through
        // unchecked (AGENTS.md invariant 1).
        "envoy.extensions.transport_sockets.tls.v3.SdsSecretConfig" => &["name", "sds_config"],
        "envoy.extensions.transport_sockets.tls.v3.TlsParameters" => &[
            "tls_minimum_protocol_version",
            "tls_maximum_protocol_version",
            "cipher_suites",
            "ecdh_curves",
        ],
        "envoy.extensions.transport_sockets.tls.v3.TlsCertificate" => {
            &["certificate_chain", "private_key"]
        }
        "envoy.extensions.transport_sockets.tls.v3.CertificateValidationContext" => &[
            "trusted_ca",
            "system_root_certs",
            "match_typed_subject_alt_names",
            "allow_expired_certificate",
        ],
        "envoy.extensions.transport_sockets.tls.v3.SubjectAltNameMatcher" => {
            &["san_type", "matcher"]
        }
        "envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector" => {
            &["max_client_hello_size"]
        }
        // Upstream HTTP protocol selection. Only the explicit
        // HTTP/1-vs-HTTP/2 selector is implemented; ALPN auto-negotiation and
        // downstream-protocol passthrough are follow-ups.
        "envoy.extensions.upstreams.http.v3.HttpProtocolOptions" => &["explicit_http_config"],
        "envoy.extensions.upstreams.http.v3.HttpProtocolOptions.ExplicitHttpConfig" => {
            &["http_protocol_options", "http2_protocol_options"]
        }
        // Bare `{}` selects the protocol; any tuning sub-field must fail
        // loudly rather than be silently ignored (same rationale as the
        // Router `&[]` entry above).
        "envoy.config.core.v3.Http1ProtocolOptions" => &[],
        "envoy.config.core.v3.Http2ProtocolOptions" => &[],
        _ => return None,
    })
}

/// Reflective walk over every SET field, rejecting fields outside the surface.
fn check_supported_surface(msg: &DynamicMessage, path: &mut String) -> Result<(), ConfigError> {
    let desc = msg.descriptor();
    let full_name = desc.full_name().to_string();

    if full_name == "google.protobuf.Any" {
        return check_any(msg, path);
    }
    if full_name.starts_with("google.protobuf.") {
        return Ok(()); // well-known leaf types
    }
    if full_name == "envoy.config.core.v3.GrpcService"
        && !path.ends_with(".grpc_service")
        && msg.has_field_by_name("timeout")
    {
        return Err(unsupported(
            format!("{path}.timeout"),
            "discovery gRPC timeout is not implemented",
        ));
    }
    let allowed = allowed_fields(&full_name);

    for field in desc.fields() {
        if !msg.has_field(&field) {
            continue;
        }
        let mark = path.len();
        if !path.is_empty() {
            path.push('.');
        }
        path.push_str(field.name());

        if let Some(allowed) = allowed {
            if !allowed.contains(&field.name()) {
                let err = ConfigError::UnsupportedField {
                    field_path: path.clone(),
                    reason: format!("`{}.{}` is not implemented yet", full_name, field.name()),
                };
                path.truncate(mark);
                return Err(err);
            }
        }

        let result = match msg.get_field(&field).as_ref() {
            Value::Message(inner) => check_supported_surface(inner, path),
            Value::List(items) => {
                let mut r = Ok(());
                for (i, item) in items.iter().enumerate() {
                    if let Value::Message(inner) = item {
                        let mark = path.len();
                        path.push_str(&format!("[{i}]"));
                        r = check_supported_surface(inner, path);
                        path.truncate(mark);
                        if r.is_err() {
                            break;
                        }
                    }
                }
                r
            }
            Value::Map(map) => {
                let mut r = Ok(());
                for value in map.values() {
                    if let Value::Message(inner) = value {
                        r = check_supported_surface(inner, path);
                        if r.is_err() {
                            break;
                        }
                    }
                }
                r
            }
            _ => Ok(()),
        };
        path.truncate(mark);
        result?;
    }
    Ok(())
}

/// Unpack an `Any` by type URL and keep walking; the path flows through the
/// containing field name (`...typed_config.<inner fields>`).
fn check_any(any: &DynamicMessage, path: &mut String) -> Result<(), ConfigError> {
    let desc = any.descriptor();
    let type_url = any
        .get_field(&desc.get_field_by_name("type_url").expect("Any.type_url"))
        .as_str()
        .unwrap_or("")
        .to_string();
    if type_url.is_empty() {
        return Ok(());
    }
    let type_name = type_url.rsplit('/').next().unwrap_or(&type_url).to_string();
    let inner_desc = proxy_api::descriptor_pool()
        .get_message_by_name(&type_name)
        .ok_or_else(|| ConfigError::UnknownTypeUrl {
            field_path: path.clone(),
            type_url: type_url.clone(),
        })?;
    let value = any.get_field(&desc.get_field_by_name("value").expect("Any.value"));
    let bytes = value.as_bytes().map(|b| b.as_ref()).unwrap_or(&[]);
    let inner = DynamicMessage::decode(inner_desc, bytes)
        .map_err(|e| ConfigError::Parse(format!("cannot decode Any `{type_url}`: {e}")))?;
    check_supported_surface(&inner, path)
}

// -------------------------------------------------------------------- utils --

fn invalid(path: impl Into<String>, reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidValue {
        field_path: path.into(),
        reason: reason.into(),
    }
}

fn unsupported(path: impl Into<String>, reason: impl Into<String>) -> ConfigError {
    ConfigError::UnsupportedField {
        field_path: path.into(),
        reason: reason.into(),
    }
}

fn to_std_duration(d: &prost_types::Duration, path: &str) -> Result<StdDuration, ConfigError> {
    if d.seconds < 0 || d.nanos < 0 {
        return Err(invalid(path, "duration must not be negative"));
    }
    Ok(StdDuration::new(d.seconds as u64, d.nanos as u32))
}

/// Envoy "unset or `0s` disables" timeout (HCM `request_headers_timeout` and
/// `request_timeout`): zero lowers to `None`, negative is an error.
fn convert_optional_timeout(
    d: Option<&prost_types::Duration>,
    path: &str,
) -> Result<Option<StdDuration>, ConfigError> {
    match d {
        None => Ok(None),
        Some(d) => {
            let v = to_std_duration(d, path)?;
            Ok((!v.is_zero()).then_some(v))
        }
    }
}

fn is_zero(d: &prost_types::Duration) -> bool {
    d.seconds == 0 && d.nanos == 0
}

/// Extract (host, port) from a `core.v3.Address` that must be a socket address.
fn socket_host_port(addr: &core_v3::Address, path: &str) -> Result<(String, u16), ConfigError> {
    use core_v3::address::Address as A;
    use core_v3::socket_address::PortSpecifier;
    match &addr.address {
        Some(A::SocketAddress(sa)) => {
            let port = match &sa.port_specifier {
                Some(PortSpecifier::PortValue(p)) => u16::try_from(*p).map_err(|_| {
                    invalid(
                        format!("{path}.socket_address.port_value"),
                        "port out of range",
                    )
                })?,
                Some(PortSpecifier::NamedPort(_)) => {
                    return Err(unsupported(
                        format!("{path}.socket_address.named_port"),
                        "named ports are not implemented",
                    ))
                }
                None => {
                    return Err(invalid(
                        format!("{path}.socket_address"),
                        "port_value is required",
                    ))
                }
            };
            Ok((sa.address.clone(), port))
        }
        Some(_) => Err(unsupported(
            path,
            "only socket_address addresses are implemented (pipes/internal listeners are not)",
        )),
        None => Err(invalid(path, "address is required")),
    }
}

fn compile_regex(pattern: &str, path: &str) -> Result<regex::Regex, ConfigError> {
    // Envoy's safe_regex is a FULL match; anchor accordingly.
    regex::Regex::new(&format!("^(?:{pattern})$"))
        .map_err(|e| invalid(path, format!("invalid regex `{pattern}`: {e}")))
}

fn decode_any<T: prost::Message + Default>(
    any: &prost_types::Any,
    path: &str,
) -> Result<T, ConfigError> {
    T::decode(any.value.as_slice())
        .map_err(|e| invalid(path, format!("cannot decode `{}`: {e}", any.type_url)))
}

fn type_name(any: &prost_types::Any) -> &str {
    any.type_url.rsplit('/').next().unwrap_or(&any.type_url)
}

/// Decode an HTTP filter's `typed_config` into a [`DynamicMessage`], keyed by
/// its type URL against the compiled descriptor pool — same lookup
/// [`check_any`] does for the generic surface walk, but returning the message
/// rather than recursing into it (that recursion already happened during the
/// surface check; this is the typed-conversion pass reusing the same bytes).
/// A type URL absent from the pool is a config error naming both the type URL
/// and the dotted path — an unrecognized HTTP filter is never silently
/// accepted just because the IR can now hold arbitrary filter config.
fn decode_http_filter_config(
    any: &prost_types::Any,
    path: &str,
) -> Result<DynamicMessage, ConfigError> {
    let inner_desc = proxy_api::descriptor_pool()
        .get_message_by_name(type_name(any))
        .ok_or_else(|| ConfigError::UnknownTypeUrl {
            field_path: path.to_string(),
            type_url: any.type_url.clone(),
        })?;
    DynamicMessage::decode(inner_desc, any.value.as_slice())
        .map_err(|e| ConfigError::Parse(format!("cannot decode `{}`: {e}", any.type_url)))
}

/// `envoy.config.route.v3.FilterConfig`'s type name -- the optional wrapper
/// around a `typed_per_filter_config` entry (see
/// [`convert_typed_per_filter_config`]).
const FILTER_CONFIG_TYPE: &str = "envoy.config.route.v3.FilterConfig";

fn convert_ext_authz(
    msg: &DynamicMessage,
    path: &str,
) -> Result<crate::authorization::ExtAuthzConfig, ConfigError> {
    use proxy_api::envoy::extensions::filters::http::ext_authz::v3::ExtAuthz;
    let cfg: ExtAuthz = msg
        .transcode_to()
        .map_err(|e| invalid(path, e.to_string()))?;
    if cfg.transport_api_version != 2 {
        return Err(unsupported(
            format!("{path}.transport_api_version"),
            "explicit V3 is required",
        ));
    }
    if !cfg.encode_raw_headers || !cfg.validate_mutations {
        let field = if !cfg.encode_raw_headers {
            "encode_raw_headers"
        } else {
            "validate_mutations"
        };
        return Err(unsupported(
            format!("{path}.{field}"),
            "this subset requires true",
        ));
    }
    for (field, value) in [
        (
            "enable_dynamic_metadata_ingestion",
            cfg.enable_dynamic_metadata_ingestion,
        ),
        (
            "charge_cluster_response_stats",
            cfg.charge_cluster_response_stats,
        ),
    ] {
        if value != Some(false) {
            return Err(unsupported(
                format!("{path}.{field}"),
                "this subset requires explicit false",
            ));
        }
    }
    let grpc = match cfg.services {
        Some(proxy_api::envoy::extensions::filters::http::ext_authz::v3::ext_authz::Services::GrpcService(g)) => g,
        _ => return Err(invalid(format!("{path}.grpc_service"), "gRPC service is required")),
    };
    let cluster = match grpc.target_specifier {
        Some(core_v3::grpc_service::TargetSpecifier::EnvoyGrpc(g))
            if !g.cluster_name.is_empty() =>
        {
            g.cluster_name
        }
        _ => {
            return Err(invalid(
                format!("{path}.grpc_service.envoy_grpc.cluster_name"),
                "nonempty Envoy gRPC cluster is required",
            ))
        }
    };
    let timeout = match grpc.timeout {
        None => StdDuration::from_millis(200),
        Some(d)
            if d.seconds >= 0
                && d.nanos >= 0
                && d.nanos < 1_000_000_000
                && d.nanos % 1_000_000 == 0 =>
        {
            StdDuration::from_secs(d.seconds as u64) + StdDuration::from_nanos(d.nanos as u64)
        }
        _ => {
            return Err(invalid(
                format!("{path}.grpc_service.timeout"),
                "timeout must be a whole number of milliseconds",
            ))
        }
    };
    if timeout < StdDuration::from_millis(1) || timeout > StdDuration::from_secs(30) {
        return Err(invalid(
            format!("{path}.grpc_service.timeout"),
            "timeout must be 1ms..=30s",
        ));
    }
    let status = cfg.status_on_error.map(|s| s.code).unwrap_or(403);
    if !(200..=511).contains(&status) {
        return Err(invalid(
            format!("{path}.status_on_error.code"),
            "final HTTP status must be 200..=511",
        ));
    }
    if cfg.stat_prefix.len() > 64
        || !cfg
            .stat_prefix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(invalid(
            format!("{path}.stat_prefix"),
            "stat prefix must contain at most 64 alphanumeric, underscore or hyphen bytes",
        ));
    }
    Ok(crate::authorization::ExtAuthzConfig {
        cluster,
        endpoint: None,
        timeout,
        connect_timeout: StdDuration::from_secs(5),
        failure_mode_allow: cfg.failure_mode_allow,
        failure_mode_allow_header_add: cfg.failure_mode_allow_header_add,
        status_on_error: status as u16,
        clear_route_cache: cfg.clear_route_cache,
        stat_prefix: cfg.stat_prefix,
        field_path: path.to_owned(),
    })
}

fn convert_ext_authz_per_route(
    msg: &DynamicMessage,
    path: &str,
) -> Result<crate::authorization::ExtAuthzPerRoute, ConfigError> {
    use proxy_api::envoy::extensions::filters::http::ext_authz::v3::{
        ext_authz_per_route::Override, ExtAuthzPerRoute,
    };
    let cfg: ExtAuthzPerRoute = msg
        .transcode_to()
        .map_err(|e| invalid(path, e.to_string()))?;
    match cfg.r#override {
        Some(Override::Disabled(true)) => Ok(crate::authorization::ExtAuthzPerRoute::Disabled),
        Some(Override::CheckSettings(c)) => {
            if c.context_extensions.len() > 64
                || c.context_extensions
                    .iter()
                    .map(|(k, v)| k.len() + v.len())
                    .sum::<usize>()
                    > 16 * 1024
            {
                return Err(invalid(
                    format!("{path}.check_settings.context_extensions"),
                    "context extensions exceed limits",
                ));
            }
            Ok(crate::authorization::ExtAuthzPerRoute::Check {
                context_extensions: c.context_extensions.into_iter().collect(),
            })
        }
        _ => Err(invalid(
            format!("{path}.disabled"),
            "set disabled: true or check_settings",
        )),
    }
}

/// Cross-resource check for an ext_authz authorization cluster. Today its only
/// caller is `validate_ext_authz_clusters`, which runs at bootstrap only;
/// listener rebuilds after xDS updates reuse the endpoint resolved here.
pub fn ext_authz_endpoint(
    cfg: &crate::authorization::ExtAuthzConfig,
    cluster: &ClusterConfig,
) -> Result<SocketAddr, ConfigError> {
    let path = format!("{}.grpc_service.envoy_grpc.cluster_name", cfg.field_path);
    if cluster.discovery != DiscoveryType::Static
        || !matches!(cluster.kind, ClusterKind::Endpoints)
        || cluster.endpoints.len() != 1
        || cluster.transport_socket.is_some()
        || cluster.upstream_protocol != UpstreamProtocol::Http2
        || cluster.health_check.is_some()
        || cluster.outlier_detection.is_some()
        || !cluster.request_headers_to_add.is_empty()
        || cluster.provider_runtime.is_some()
        || cluster.request_path_rewrite.is_some()
        || cluster.usage_dialect.is_some()
        || cluster.circuit_breakers != CircuitBreakers::default()
        || cluster.per_connection_buffer_limit_bytes != 1024 * 1024
    {
        return Err(unsupported(path, "authorization requires one STATIC plaintext HTTP/2 endpoint without health, outlier or provider behavior"));
    }
    let endpoint = &cluster.endpoints[0];
    let ip: IpAddr = endpoint
        .host
        .parse()
        .map_err(|_| invalid(&path, "authorization endpoint must be an IP address"))?;
    Ok(SocketAddr::new(ip, endpoint.port))
}

fn validate_ext_authz_clusters(snapshot: &mut ConfigSnapshot) -> Result<(), ConfigError> {
    for listener in snapshot.listeners.values_mut() {
        let listener = Arc::get_mut(listener).expect("fresh bootstrap listener");
        for chain in listener
            .filter_chains
            .iter_mut()
            .chain(listener.default_filter_chain.iter_mut())
        {
            for network in &mut chain.filters {
                if let NetworkFilterSpec::HttpConnectionManager(hcm) = network {
                    for filter in &mut hcm.http_filters {
                        if let Some(cfg) = &mut filter.ext_authz {
                            let cluster = snapshot.clusters.get(&cfg.cluster).ok_or_else(|| {
                                invalid(
                                    format!(
                                        "{}.grpc_service.envoy_grpc.cluster_name",
                                        cfg.field_path
                                    ),
                                    "authorization cluster is not defined",
                                )
                            })?;
                            cfg.endpoint = Some(ext_authz_endpoint(cfg, cluster)?);
                            cfg.connect_timeout = cluster.connect_timeout;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Lower one level of Envoy's `typed_per_filter_config` map (present on
/// `Route`, `VirtualHost`, and `RouteConfiguration`) into IR
/// [`PerFilterConfig`] entries, keyed by filter name. `path` is the dotted
/// path of the owning `typed_per_filter_config` field itself; each entry's
/// error path is `{path}[{name}]`, matching AGENTS.md invariant 1.
///
/// Rust note: the return type is a [`std::collections::BTreeMap`], not a
/// `HashMap` -- `m`'s iteration order is unspecified (it's a `HashMap`,
/// mirroring the proto's `map<string, Any>`), but the IR needs deterministic
/// `Debug`/iteration order for `/config_dump` and test assertions, so the
/// entries are collected into a map that sorts itself by key.
fn convert_typed_per_filter_config(
    m: &std::collections::HashMap<String, prost_types::Any>,
    path: &str,
) -> Result<std::collections::BTreeMap<String, PerFilterConfig>, ConfigError> {
    let mut out = std::collections::BTreeMap::new();
    for (name, any) in m {
        let entry_path = format!("{path}[{name}]");
        let per = if type_name(any) == FILTER_CONFIG_TYPE {
            let wrapper: route_v3::FilterConfig = decode_any(any, &entry_path)?;
            let has_config = wrapper
                .config
                .as_ref()
                .is_some_and(|a| !a.type_url.is_empty());
            match (has_config, wrapper.disabled) {
                (true, true) => {
                    return Err(invalid(
                        &entry_path,
                        "cannot set both `config` and `disabled`",
                    ))
                }
                (false, false) => {
                    return Err(invalid(
                        &entry_path,
                        "a FilterConfig must set either `config` or `disabled`",
                    ))
                }
                (true, false) => {
                    let inner = wrapper.config.as_ref().expect("has_config checked above");
                    let config = decode_http_filter_config(
                        inner,
                        &format!("{entry_path}.config.typed_config"),
                    )?;
                    PerFilterConfig {
                        ext_authz: None,
                        type_url: inner.type_url.clone(),
                        config: Some(config),
                        is_optional: wrapper.is_optional,
                        disabled: false,
                    }
                }
                (false, true) => PerFilterConfig {
                    ext_authz: None,
                    type_url: String::new(),
                    config: None,
                    is_optional: wrapper.is_optional,
                    disabled: true,
                },
            }
        } else {
            let config = decode_http_filter_config(any, &entry_path)?;
            PerFilterConfig {
                ext_authz: None,
                type_url: any.type_url.clone(),
                config: Some(config),
                is_optional: false,
                disabled: false,
            }
        };
        let mut per = per;
        if per.type_url == crate::authorization::PER_ROUTE_TYPE_URL {
            let msg = per.config.take().expect("decoded per-route message");
            let config_path = if type_name(any) == FILTER_CONFIG_TYPE {
                format!("{entry_path}.config.typed_config")
            } else {
                entry_path.clone()
            };
            per.ext_authz = Some(convert_ext_authz_per_route(&msg, &config_path)?);
        }
        out.insert(name.clone(), per);
    }
    Ok(out)
}

// ---------------------------------------------------------------- listeners --

const TCP_PROXY_TYPE: &str = "envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy";
const HCM_TYPE: &str =
    "envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager";
const ROUTER_TYPE: &str = "envoy.extensions.filters.http.router.v3.Router";
const DOWNSTREAM_TLS_TYPE: &str = "envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext";
const UPSTREAM_TLS_TYPE: &str = "envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext";
const TLS_INSPECTOR_TYPE: &str = "envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector";
// Access logging sinks we implement.
const FILE_ACCESS_LOG_TYPE: &str = "envoy.extensions.access_loggers.file.v3.FileAccessLog";
const STDOUT_ACCESS_LOG_TYPE: &str = "envoy.extensions.access_loggers.stream.v3.StdoutAccessLog";
const STDERR_ACCESS_LOG_TYPE: &str = "envoy.extensions.access_loggers.stream.v3.StderrAccessLog";

/// Envoy default for `per_connection_buffer_limit_bytes`: 1 MiB.
const DEFAULT_CONN_BUFFER_LIMIT: u32 = 1024 * 1024;
/// Envoy default cluster connect timeout: 5s.
const DEFAULT_CONNECT_TIMEOUT: StdDuration = StdDuration::from_secs(5);
/// Envoy default route timeout: 15s (S4).
const DEFAULT_ROUTE_TIMEOUT: StdDuration = StdDuration::from_secs(15);
/// Envoy default `HealthCheck.no_traffic_interval` (S6): 60s.
const DEFAULT_NO_TRAFFIC_INTERVAL: StdDuration = StdDuration::from_secs(60);

fn convert_listener(l: &listener_v3::Listener, path: &str) -> Result<ListenerConfig, ConfigError> {
    let addr_path = format!("{path}.address");
    let address = l
        .address
        .as_ref()
        .ok_or_else(|| invalid(&addr_path, "listener address is required"))?;
    let (host, port) = socket_host_port(address, &addr_path)?;
    let ip: IpAddr = host.parse().map_err(|_| {
        invalid(
            format!("{addr_path}.socket_address.address"),
            "listener address must be an IP, not a hostname",
        )
    })?;

    // Envoy accepts an explicit 0 (documented as a soft limit); we use the
    // value as the HTTP body buffer cap, so 0 would 413 every request body.
    // Unset keeps the default; only an explicit 0 is rejected.
    if l.per_connection_buffer_limit_bytes == Some(0) {
        return Err(invalid(
            format!("{path}.per_connection_buffer_limit_bytes"),
            "0 would reject every request body; omit the field to use the 1 MiB default",
        ));
    }

    let mut filter_chains = Vec::new();
    for (i, fc) in l.filter_chains.iter().enumerate() {
        filter_chains.push(convert_filter_chain(
            fc,
            &format!("{path}.filter_chains[{i}]"),
        )?);
    }
    // Envoy rejects two filter chains with byte-identical match criteria at
    // listener creation; catching it here keeps the matcher total.
    for i in 0..filter_chains.len() {
        for j in (i + 1)..filter_chains.len() {
            if filter_chains[i].match_criteria == filter_chains[j].match_criteria {
                return Err(invalid(
                    path,
                    format!(
                        "listener `{}` has duplicate filter_chain_match criteria between filter_chains[{i}] and filter_chains[{j}]",
                        l.name
                    ),
                ));
            }
        }
    }

    let default_filter_chain = l
        .default_filter_chain
        .as_ref()
        .map(|fc| convert_filter_chain(fc, &format!("{path}.default_filter_chain")))
        .transpose()?;
    // Envoy silently ignores match criteria on default_filter_chain; ground
    // rule #2 says we reject instead of dropping it quietly.
    if let Some(dfc) = &default_filter_chain {
        if dfc.match_criteria != FilterChainMatch::default() {
            return Err(invalid(
                format!("{path}.default_filter_chain.filter_chain_match"),
                "default_filter_chain must not specify match criteria (Envoy ignores it; we reject it instead of silently dropping it)",
            ));
        }
    }

    let listener_filters =
        convert_listener_filters(l, &filter_chains, default_filter_chain.as_ref(), path)?;

    Ok(ListenerConfig {
        name: l.name.clone(),
        address: SocketAddr::new(ip, port),
        filter_chains,
        default_filter_chain,
        listener_filters,
        per_connection_buffer_limit_bytes: l
            .per_connection_buffer_limit_bytes
            .unwrap_or(DEFAULT_CONN_BUFFER_LIMIT),
        tcp_backlog_size: l.tcp_backlog_size,
        // Envoy default: true.
        bind_to_port: l.bind_to_port.unwrap_or(true),
        ignore_global_conn_limit: l.ignore_global_conn_limit,
    })
}

const GLOBAL_DOWNSTREAM_MAX_CONNECTIONS_MONITOR: &str =
    "envoy.resource_monitors.global_downstream_max_connections";
const DOWNSTREAM_CONNECTIONS_TYPE: &str =
    "envoy.extensions.resource_monitors.downstream_connections.v3.DownstreamConnectionsConfig";

/// Lower bootstrap `overload_manager` into the global downstream connection
/// cap. Only one `resource_monitors` entry is supported:
/// `envoy.resource_monitors.global_downstream_max_connections`. The surface
/// walk already refused every other `OverloadManager` field; unknown monitor
/// names, duplicates and a zero limit (the proto requires `> 0`) are refused
/// here with the offending field's path.
fn convert_overload_manager(
    om: Option<&proxy_api::envoy::config::overload::v3::OverloadManager>,
    path: &str,
) -> Result<Option<u64>, ConfigError> {
    use proxy_api::envoy::config::overload::v3::resource_monitor::ConfigType;
    let Some(om) = om else { return Ok(None) };
    let mut limit: Option<u64> = None;
    let mut first_at = 0usize;
    for (i, monitor) in om.resource_monitors.iter().enumerate() {
        let m_path = format!("{path}.resource_monitors[{i}]");
        if monitor.name != GLOBAL_DOWNSTREAM_MAX_CONNECTIONS_MONITOR {
            return Err(unsupported(
                format!("{m_path}.name"),
                format!(
                    "resource monitor `{}` is not implemented; only `{GLOBAL_DOWNSTREAM_MAX_CONNECTIONS_MONITOR}` is supported",
                    monitor.name
                ),
            ));
        }
        if limit.is_some() {
            return Err(invalid(
                &m_path,
                format!("duplicate `{GLOBAL_DOWNSTREAM_MAX_CONNECTIONS_MONITOR}` monitor; already configured at resource_monitors[{first_at}]"),
            ));
        }
        let t_path = format!("{m_path}.typed_config");
        let Some(ConfigType::TypedConfig(any)) = &monitor.config_type else {
            return Err(invalid(&t_path, "resource monitor requires typed_config"));
        };
        if type_name(any) != DOWNSTREAM_CONNECTIONS_TYPE {
            return Err(ConfigError::UnknownTypeUrl {
                field_path: t_path,
                type_url: any.type_url.clone(),
            });
        }
        let cfg: downstream_connections_v3::DownstreamConnectionsConfig = decode_any(any, &t_path)?;
        let max = u64::try_from(cfg.max_active_downstream_connections)
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(|| {
                invalid(
                    format!("{t_path}.max_active_downstream_connections"),
                    "must be greater than 0 (Envoy requires an explicit positive limit)",
                )
            })?;
        first_at = i;
        limit = Some(max);
    }
    Ok(limit)
}

/// Convert `Listener.listener_filters` (pre-connection filters run against
/// the raw socket before filter-chain matching), plus Envoy's `tls_inspector`
/// auto-injection: if no `tls_inspector` was configured explicitly but a
/// filter chain matches on SNI/ALPN/`transport_protocol: tls`, Envoy inserts
/// a default one so that matching still works — see the doc comment on
/// [`ListenerFilterSpec`] and `internal-docs/envoy-divergences.md`.
fn convert_listener_filters(
    l: &listener_v3::Listener,
    filter_chains: &[FilterChainSpec],
    default_chain: Option<&FilterChainSpec>,
    path: &str,
) -> Result<Vec<ListenerFilterSpec>, ConfigError> {
    let mut out = Vec::new();
    // Rust note: track the index of the first explicit tls_inspector (if any)
    // so a second one can be reported with both indices, mirroring the
    // duplicate-filter-chain-match check above.
    let mut tls_inspector_at: Option<usize> = None;

    for (i, lf) in l.listener_filters.iter().enumerate() {
        let lf_path = format!("{path}.listener_filters[{i}]");
        use listener_v3::listener_filter::ConfigType;
        let any = match &lf.config_type {
            Some(ConfigType::TypedConfig(any)) => any,
            Some(_) => {
                return Err(unsupported(
                    format!("{lf_path}.config_discovery"),
                    "listener filter config discovery (ECDS) is not implemented",
                ))
            }
            None => return Err(invalid(&lf_path, "listener filter requires typed_config")),
        };
        let cfg_path = format!("{lf_path}.typed_config");

        match type_name(any) {
            TLS_INSPECTOR_TYPE => {
                if let Some(prev) = tls_inspector_at {
                    return Err(invalid(
                        path,
                        format!(
                            "listener `{}` has duplicate tls_inspector listener filters at listener_filters[{prev}] and listener_filters[{i}]",
                            l.name
                        ),
                    ));
                }
                tls_inspector_at = Some(i);
                let ti: tls_inspector_v3::TlsInspector = decode_any(any, &cfg_path)?;
                let max_client_hello_size = match ti.max_client_hello_size {
                    Some(size) => {
                        if !(256..=16384).contains(&size) {
                            return Err(invalid(
                                format!("{cfg_path}.max_client_hello_size"),
                                "max_client_hello_size must be in [256, 16384]",
                            ));
                        }
                        size
                    }
                    None => TlsInspectorConfig::default().max_client_hello_size,
                };
                out.push(ListenerFilterSpec::TlsInspector(TlsInspectorConfig {
                    max_client_hello_size,
                }));
            }
            _ => {
                return Err(ConfigError::UnknownTypeUrl {
                    field_path: cfg_path,
                    type_url: any.type_url.clone(),
                })
            }
        }
    }

    // Envoy parity: auto-insert a default tls_inspector when a filter chain
    // matches on SNI/ALPN/`transport_protocol: tls` and none is configured —
    // omitting it would silently make those criteria never match TLS traffic.
    if tls_inspector_at.is_none() {
        let needs_tls_inspector = filter_chains
            .iter()
            .chain(default_chain)
            .any(|fc| filter_chain_match_needs_tls_inspector(&fc.match_criteria));
        if needs_tls_inspector {
            out.push(ListenerFilterSpec::TlsInspector(
                TlsInspectorConfig::default(),
            ));
        }
    }

    Ok(out)
}

fn filter_chain_match_needs_tls_inspector(m: &FilterChainMatch) -> bool {
    !m.server_names.is_empty()
        || !m.application_protocols.is_empty()
        || m.transport_protocol.as_deref() == Some("tls")
}

fn convert_filter_chain(
    fc: &listener_v3::FilterChain,
    path: &str,
) -> Result<FilterChainSpec, ConfigError> {
    let match_criteria = match &fc.filter_chain_match {
        Some(m) => convert_filter_chain_match(m, &format!("{path}.filter_chain_match"))?,
        None => FilterChainMatch::default(),
    };

    let transport_socket = fc
        .transport_socket
        .as_ref()
        .map(|ts| convert_downstream_tls(ts, &format!("{path}.transport_socket")))
        .transpose()?;

    // Unset stays `None` (the listener applies its default); an explicit
    // `0s` is kept as `Some(ZERO)` so "no deadline" is a deliberate choice.
    let transport_socket_connect_timeout = fc
        .transport_socket_connect_timeout
        .as_ref()
        .map(|d| to_std_duration(d, &format!("{path}.transport_socket_connect_timeout")))
        .transpose()?;

    if fc.filters.is_empty() {
        return Err(invalid(
            format!("{path}.filters"),
            "filter chain has no filters",
        ));
    }
    if fc.filters.len() > 1 {
        // Both supported filters are terminal; non-terminal L4 filters are not implemented.
        return Err(unsupported(
            format!("{path}.filters[1]"),
            "multiple network filters are not implemented yet",
        ));
    }
    let mut filters = Vec::new();
    for (i, f) in fc.filters.iter().enumerate() {
        filters.push(convert_network_filter(f, &format!("{path}.filters[{i}]"))?);
    }

    Ok(FilterChainSpec {
        name: (!fc.name.is_empty()).then(|| fc.name.clone()),
        match_criteria,
        transport_socket,
        transport_socket_connect_timeout,
        filters,
    })
}

/// The full 9-criteria `FilterChainMatch`. `address_suffix`/`suffix_len`
/// remain unimplemented (Envoy itself marks them `#not-implemented-hide`) and
/// are rejected rather than silently dropped (AGENTS.md invariant 1).
fn convert_filter_chain_match(
    m: &listener_v3::FilterChainMatch,
    path: &str,
) -> Result<FilterChainMatch, ConfigError> {
    if !m.address_suffix.is_empty() {
        return Err(unsupported(
            format!("{path}.address_suffix"),
            "address_suffix matching is not implemented",
        ));
    }
    if m.suffix_len.is_some() {
        return Err(unsupported(
            format!("{path}.suffix_len"),
            "suffix_len matching is not implemented",
        ));
    }

    if let Some(port) = m.destination_port {
        if port > 65535 {
            return Err(invalid(
                format!("{path}.destination_port"),
                "port must be <= 65535",
            ));
        }
    }
    for (i, port) in m.source_ports.iter().enumerate() {
        if *port > 65535 {
            return Err(invalid(
                format!("{path}.source_ports[{i}]"),
                "port must be <= 65535",
            ));
        }
    }

    for (i, name) in m.server_names.iter().enumerate() {
        validate_server_name(name, &format!("{path}.server_names[{i}]"))?;
    }

    let prefix_ranges = convert_cidr_ranges(&m.prefix_ranges, &format!("{path}.prefix_ranges"))?;
    let direct_source_prefix_ranges = convert_cidr_ranges(
        &m.direct_source_prefix_ranges,
        &format!("{path}.direct_source_prefix_ranges"),
    )?;
    let source_prefix_ranges = convert_cidr_ranges(
        &m.source_prefix_ranges,
        &format!("{path}.source_prefix_ranges"),
    )?;

    use listener_v3::filter_chain_match::ConnectionSourceType as ProtoSourceType;
    let source_type = match ProtoSourceType::try_from(m.source_type) {
        Ok(ProtoSourceType::Any) => SourceType::Any,
        Ok(ProtoSourceType::SameIpOrLoopback) => SourceType::SameIpOrLoopback,
        Ok(ProtoSourceType::External) => SourceType::External,
        Err(_) => {
            return Err(invalid(
                format!("{path}.source_type"),
                "unknown source_type enum value",
            ))
        }
    };

    Ok(FilterChainMatch {
        destination_port: m.destination_port,
        prefix_ranges,
        server_names: m.server_names.clone(),
        transport_protocol: (!m.transport_protocol.is_empty())
            .then(|| m.transport_protocol.clone()),
        application_protocols: m.application_protocols.clone(),
        direct_source_prefix_ranges,
        source_type,
        source_prefix_ranges,
        source_ports: m.source_ports.clone(),
    })
}

/// `server_names` entries must be an exact name or a `*.`-prefixed suffix
/// wildcard (e.g. `*.example.com`); Envoy rejects any other use of `*`
/// (a bare `*`, `a.*.b`, `*example.com`).
fn validate_server_name(name: &str, path: &str) -> Result<(), ConfigError> {
    let valid = match name.strip_prefix("*.") {
        Some(rest) => !rest.is_empty() && !rest.contains('*'),
        None => !name.contains('*'),
    };
    if !valid {
        return Err(invalid(
            path,
            format!(
                "`{name}` is not a valid server name; only exact names or `*.`-prefixed suffix wildcards are supported"
            ),
        ));
    }
    Ok(())
}

fn convert_cidr_ranges(
    ranges: &[core_v3::CidrRange],
    path: &str,
) -> Result<Vec<CidrRange>, ConfigError> {
    ranges
        .iter()
        .enumerate()
        .map(|(i, cr)| convert_cidr_range(cr, &format!("{path}[{i}]")))
        .collect()
}

fn convert_cidr_range(cr: &core_v3::CidrRange, path: &str) -> Result<CidrRange, ConfigError> {
    let addr: IpAddr = cr.address_prefix.parse().map_err(|_| {
        invalid(
            format!("{path}.address_prefix"),
            format!("`{}` is not a valid IP address", cr.address_prefix),
        )
    })?;
    let max_prefix: u32 = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    let prefix_len = cr.prefix_len.unwrap_or(0);
    if prefix_len > max_prefix {
        return Err(invalid(
            format!("{path}.prefix_len"),
            format!("prefix_len must be <= {max_prefix} for this address family"),
        ));
    }
    Ok(CidrRange {
        addr,
        // Rust note: `as` truncates, but the bounds check above already
        // guarantees `prefix_len <= 128`, so no information is lost.
        prefix_len: prefix_len as u8,
    })
}

fn convert_network_filter(
    f: &listener_v3::Filter,
    path: &str,
) -> Result<NetworkFilterSpec, ConfigError> {
    use listener_v3::filter::ConfigType;
    let any = match &f.config_type {
        Some(ConfigType::TypedConfig(any)) => any,
        Some(_) => {
            return Err(unsupported(
                format!("{path}.config_discovery"),
                "filter config discovery (ECDS) is not implemented",
            ))
        }
        None => return Err(invalid(path, "filter requires typed_config")),
    };
    let cfg_path = format!("{path}.typed_config");
    match type_name(any) {
        TCP_PROXY_TYPE => {
            let tp: tcp_proxy_v3::TcpProxy = decode_any(any, &cfg_path)?;
            Ok(NetworkFilterSpec::TcpProxy(convert_tcp_proxy(
                &tp, &cfg_path,
            )?))
        }
        HCM_TYPE => {
            let hcm: hcm_v3::HttpConnectionManager = decode_any(any, &cfg_path)?;
            Ok(NetworkFilterSpec::HttpConnectionManager(convert_hcm(
                &hcm, &cfg_path,
            )?))
        }
        _ => Err(ConfigError::UnknownTypeUrl {
            field_path: cfg_path,
            type_url: any.type_url.clone(),
        }),
    }
}

fn convert_tcp_proxy(
    tp: &tcp_proxy_v3::TcpProxy,
    path: &str,
) -> Result<TcpProxyConfig, ConfigError> {
    use tcp_proxy_v3::tcp_proxy::ClusterSpecifier;
    let cluster = match &tp.cluster_specifier {
        Some(ClusterSpecifier::Cluster(name)) => name.clone(),
        Some(ClusterSpecifier::WeightedClusters(_)) => {
            return Err(unsupported(
                format!("{path}.weighted_clusters"),
                "tcp_proxy weighted clusters are not implemented yet",
            ))
        }
        None => return Err(invalid(format!("{path}.cluster"), "cluster is required")),
    };
    let idle_timeout = match &tp.idle_timeout {
        Some(d) if is_zero(d) => None,
        Some(d) => Some(to_std_duration(d, &format!("{path}.idle_timeout"))?),
        // Envoy default: 1h.
        None => Some(StdDuration::from_secs(3600)),
    };
    // Envoy default 1 (a single attempt, no retry); proto floor is 1, so a
    // configured 0 is a validation error caught before lowering. Treat unset
    // and 0 alike as the default rather than "zero attempts".
    let max_connect_attempts = match tp.max_connect_attempts {
        Some(n) if n >= 1 => n,
        _ => 1,
    };
    Ok(TcpProxyConfig {
        stat_prefix: tp.stat_prefix.clone(),
        cluster,
        idle_timeout,
        max_connect_attempts,
    })
}

fn convert_hcm(
    hcm: &hcm_v3::HttpConnectionManager,
    path: &str,
) -> Result<HttpConnectionManagerConfig, ConfigError> {
    use hcm_v3::http_connection_manager::CodecType as ProtoCodecType;
    use hcm_v3::http_connection_manager::RouteSpecifier;
    // (see `check_lane_h_filter_order` below for the ordering rules these
    // three type URLs participate in)
    let (route_table, rds_route_config_name) = match &hcm.route_specifier {
        Some(RouteSpecifier::RouteConfig(rc)) => (
            convert_route_table(rc, &format!("{path}.route_config"))?,
            None,
        ),
        Some(RouteSpecifier::Rds(rds)) => {
            let rds_path = format!("{path}.rds");
            let source = check_ads_source(
                rds.config_source.as_ref(),
                &format!("{rds_path}.config_source"),
            )?;
            if source.is_none() {
                return Err(invalid(
                    format!("{rds_path}.config_source"),
                    "RDS requires an ADS config_source",
                ));
            }
            if source
                .as_ref()
                .is_some_and(|source| source.initial_fetch_timeout.is_some())
            {
                return Err(unsupported(
                    format!("{rds_path}.config_source.initial_fetch_timeout"),
                    "per-route initial_fetch_timeout is not implemented; use the bootstrap LDS/CDS timeout",
                ));
            }
            if rds.route_config_name.is_empty() {
                return Err(invalid(
                    format!("{rds_path}.route_config_name"),
                    "RDS requires a non-empty route_config_name",
                ));
            }
            // Workers never use this table: ResourceApplier stages the
            // listener until the named RDS resource is present.
            (
                RouteTable::new(rds.route_config_name.clone(), Vec::new(), BTreeMap::new())
                    .expect("an empty RDS placeholder route table is valid"),
                Some(rds.route_config_name.clone()),
            )
        }
        Some(RouteSpecifier::ScopedRoutes(_)) => {
            return Err(unsupported(
                format!("{path}.scoped_routes"),
                "scoped routes are not implemented",
            ))
        }
        None => return Err(invalid(path, "route_config is required")),
    };

    let mut http_filters = Vec::new();
    for (i, f) in hcm.http_filters.iter().enumerate() {
        let f_path = format!("{path}.http_filters[{i}]");
        use hcm_v3::http_filter::ConfigType;
        let any = match &f.config_type {
            Some(ConfigType::TypedConfig(any)) => any,
            Some(_) => {
                return Err(unsupported(
                    format!("{f_path}.config_discovery"),
                    "HTTP filter config discovery (ECDS) is not implemented",
                ))
            }
            None => return Err(invalid(&f_path, "http filter requires typed_config")),
        };
        let is_router = type_name(any) == ROUTER_TYPE;
        // Rust note: the router has no configurable fields (`allowed_fields`
        // maps its type to `&[]`), so its `config` is always `None`; every
        // other filter's `typed_config` is decoded reflectively here — the
        // registry (`proxy-http::FilterRegistry`), not this lowering pass,
        // is what actually understands the bytes (AGENTS.md invariant 2).
        let mut config = if is_router {
            None
        } else {
            Some(decode_http_filter_config(
                any,
                &format!("{f_path}.typed_config"),
            )?)
        };
        let ext_authz = if any.type_url == crate::authorization::TYPE_URL {
            if i != 0 {
                return Err(unsupported(
                    format!("{f_path}.typed_config"),
                    "ext_authz must be the first HTTP filter in the decoder chain",
                ));
            }
            Some(convert_ext_authz(
                &config.take().expect("decoded config"),
                &format!("{f_path}.typed_config"),
            )?)
        } else {
            None
        };
        http_filters.push(HttpFilterSpec {
            ext_authz,
            name: f.name.clone(),
            type_url: any.type_url.clone(),
            config,
            is_router,
        });
    }

    // Envoy requires exactly one terminal router filter, and it must be last.
    let router_positions: Vec<usize> = http_filters
        .iter()
        .enumerate()
        .filter(|(_, f)| f.is_router)
        .map(|(i, _)| i)
        .collect();
    match router_positions.as_slice() {
        [] => {
            return Err(invalid(
                format!("{path}.http_filters"),
                "the last HTTP filter must be the router (envoy.filters.http.router)",
            ))
        }
        [pos] if *pos == http_filters.len() - 1 => {}
        [pos] => {
            return Err(invalid(
                format!("{path}.http_filters[{pos}]"),
                "the router filter (envoy.filters.http.router) must be the last HTTP filter",
            ))
        }
        _ => {
            return Err(invalid(
                format!("{path}.http_filters"),
                "the router filter (envoy.filters.http.router) may appear at most once",
            ))
        }
    }

    check_lane_h_filter_order(&http_filters, path)?;

    // `codec_type` is a plain (non-wrapped) proto3 enum, so its
    // zero-value (0 == AUTO) IS the Envoy default -- no `unwrap_or` needed,
    // unlike the `BoolValue`s just below. `HTTP3` has no IR variant at all
    // (see `CodecType`'s doc): this proxy has no QUIC listener to speak it
    // over, so accepting the value and quietly falling back to `AUTO` would
    // be exactly the silent-drop AGENTS.md invariant 1 forbids -- it must error with
    // its dotted path instead.
    let codec_type = match ProtoCodecType::try_from(hcm.codec_type) {
        Ok(ProtoCodecType::Auto) => CodecType::Auto,
        Ok(ProtoCodecType::Http1) => CodecType::Http1,
        Ok(ProtoCodecType::Http2) => CodecType::Http2,
        Ok(ProtoCodecType::Http3) => {
            return Err(unsupported(
                format!("{path}.codec_type"),
                "HTTP3 is not implemented (this proxy has no QUIC/UDP listener)",
            ))
        }
        Err(_) => {
            return Err(invalid(
                format!("{path}.codec_type"),
                "unknown codec_type value",
            ))
        }
    };

    // Envoy default true; the proto field is a `BoolValue`, so unset means
    // "generate" and a present value takes precedence, including an explicit
    // `false`.
    let generate_request_id = hcm.generate_request_id.unwrap_or(true);

    // Envoy default false: `use_remote_address` is a `BoolValue`, so unset
    // means "do not mutate XFF/x-forwarded-proto at this HCM".
    let use_remote_address = hcm.use_remote_address.unwrap_or(false);
    // Plain `u32` (not wrapped), so the proto zero-value is already the
    // Envoy default of 0 trusted hops.
    let xff_num_trusted_hops = hcm.xff_num_trusted_hops;

    let access_logs = convert_access_logs(&hcm.access_log, &format!("{path}.access_log"))?;

    // `tracing.provider.typed_config` would need to
    // resolve `envoy.config.trace.v3.OpenTelemetryConfig`, which is not
    // compiled into the descriptor pool -- see the allow-list comment on
    // `HttpConnectionManager.Tracing` above for how that was confirmed.
    // Rejecting here (rather than leaving `tracing` off the allow list
    // entirely, which would produce this same class of error) means the
    // message can point an operator at the actual supported path instead of
    // the generic "not implemented yet" text -- same reasoning as the
    // RING_HASH/MAGLEV rejection in `convert_cluster`.
    if hcm.tracing.is_some() {
        return Err(unsupported(
            format!("{path}.tracing"),
            "OTLP tracing is not implemented in Envoy mode yet (the \
             `envoy.config.trace.v3.OpenTelemetryConfig` tracer extension proto is not \
             compiled into the descriptor pool). Use the `llmproxy` dialect's \
             `observability.tracing` block instead, which builds the same IR without going \
             through this proto.",
        ));
    }

    let upgrade_configs =
        convert_upgrade_configs(&hcm.upgrade_configs, &format!("{path}.upgrade_configs"))?;

    Ok(HttpConnectionManagerConfig {
        stat_prefix: hcm.stat_prefix.clone(),
        route_table: Arc::new(route_table),
        rds_route_config_name,
        http_filters,
        codec_type,
        generate_request_id,
        use_remote_address,
        access_logs,
        xff_num_trusted_hops,
        upgrade_configs,
        request_headers_timeout: convert_optional_timeout(
            hcm.request_headers_timeout.as_ref(),
            &format!("{path}.request_headers_timeout"),
        )?,
        request_timeout: convert_optional_timeout(
            hcm.request_timeout.as_ref(),
            &format!("{path}.request_timeout"),
        )?,
        // Envoy's own default is 5 minutes, and only an explicit `0s`
        // disables it.
        stream_idle_timeout: match hcm.stream_idle_timeout.as_ref() {
            None => Some(StdDuration::from_secs(300)),
            some => convert_optional_timeout(some, &format!("{path}.stream_idle_timeout"))?,
        },
        max_stream_duration: convert_optional_timeout(
            hcm.common_http_protocol_options
                .as_ref()
                .and_then(|o| o.max_stream_duration.as_ref()),
            &format!("{path}.common_http_protocol_options.max_stream_duration"),
        )?,
    })
}

/// S10: lower an HCM's `upgrade_configs`. `upgrade_type` is required and
/// stored lowercased (Envoy matches it case-insensitively); `enabled` is a
/// `BoolValue` defaulting to true; a duplicate `upgrade_type` is a config
/// error, as it is in Envoy. Per-upgrade `filters` are already rejected by the
/// surface walk (see the `UpgradeConfig` allow-list entry), so they never
/// reach here.
fn convert_upgrade_configs(
    protos: &[hcm_v3::http_connection_manager::UpgradeConfig],
    path: &str,
) -> Result<Vec<UpgradeConfig>, ConfigError> {
    let mut out = Vec::with_capacity(protos.len());
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (i, uc) in protos.iter().enumerate() {
        let p = format!("{path}[{i}]");
        if uc.upgrade_type.is_empty() {
            return Err(invalid(
                format!("{p}.upgrade_type"),
                "upgrade_type is required and must be non-empty",
            ));
        }
        let upgrade_type = uc.upgrade_type.to_ascii_lowercase();
        if !seen.insert(upgrade_type.clone()) {
            return Err(invalid(
                format!("{p}.upgrade_type"),
                format!("duplicate upgrade_type `{upgrade_type}` (matched case-insensitively)"),
            ));
        }
        // `enabled` is a `BoolValue` -> prost `Option<bool>`; absent = true.
        let enabled = uc.enabled.unwrap_or(true);
        out.push(UpgradeConfig {
            upgrade_type,
            enabled,
        });
    }
    Ok(out)
}

// ------------------------------------------------- llmproxy filter ordering --

// The llmproxy filter type URLs this pass knows about.
//
// Duplicated as string literals rather than imported from `proxy-filters`,
// which is the crate that actually defines them: `proxy-filters` depends on
// `proxy-config`, so the dependency cannot point this way (AGENTS.md invariant 2).
// The canonical definitions are `proxy_filters::{auth_filter, usage_filter,
// token_limit_filter, body_rewrite_filter, model_authz_filter}::TYPE_URL`;
// `tests::lane_h_type_urls_match_the_filters` in `proxy-filters` pins them
// equal, so a rename cannot silently disable these checks.
// `pub` solely so `tests/lane_h_filter_order.rs` can assert THESE constants
// equal to the filters' own -- pinning a private copy the test re-declares
// would pin nothing.
pub const AUTH_FILTER_TYPE: &str = "type.llmproxy.dev/llmproxy.filters.v0.Authentication";
pub const TOKEN_LIMIT_FILTER_TYPE: &str = "type.llmproxy.dev/llmproxy.filters.v0.TokenLimit";
/// One-release compatibility alias for the token-limit migration.
/// Kept public so the ordering tests pin its relationship to the filter
/// factory just as they pin the canonical type URL.
pub const LEGACY_TOKEN_LIMIT_FILTER_TYPE: &str =
    "type.llmproxy.dev/envoy.config.core.v3.RateLimitSettings";
pub const USAGE_FILTER_TYPE: &str = "type.llmproxy.dev/llmproxy.filters.v0.Usage";
/// One-release compatibility alias for the usage-filter migration.
pub const LEGACY_USAGE_FILTER_TYPE: &str = "type.llmproxy.dev/envoy.config.core.v3.DataSource";
pub const BODY_REWRITE_FILTER_TYPE: &str = "type.llmproxy.dev/llmproxy.filters.v0.BodyRewrite";
/// One-release compatibility alias for the body-rewrite migration.
pub const LEGACY_BODY_REWRITE_FILTER_TYPE: &str =
    "type.llmproxy.dev/envoy.config.core.v3.RuntimeFeatureFlag";
pub const MODEL_AUTHZ_FILTER_TYPE: &str = "type.llmproxy.dev/llmproxy.filters.v0.ModelAuthz";
pub const MODEL_RESOLVER_FILTER_TYPE: &str = "type.llmproxy.dev/llmproxy.filters.v0.ModelResolver";
pub const SPEND_LIMIT_FILTER_TYPE: &str = "type.llmproxy.dev/llmproxy.filters.v0.SpendLimit";

/// Rejects llmproxy filter chains whose order silently disables a filter.
///
/// # Why this is a config error and not a doc comment
///
/// Both orderings below fail *silently* when they are wrong. Nothing errors at
/// runtime, no log line appears, and every request succeeds — the affected
/// filter simply reads `None` out of `StreamInfo` forever and does something
/// plausible-looking with it. That is AGENTS.md invariant 1's failure mode exactly
/// (a config that means one thing and does another), and the only place it can
/// be caught is here, where the whole chain is visible at once. A filter
/// factory sees only its own `typed_config`; `FactoryContext` carries no view
/// of its neighbours.
///
/// # The two rules run in OPPOSITE directions, and that is not a mistake
///
/// S2.1: **decoder** callbacks run in config order, **encoder** callbacks in
/// *reverse* config order. So "must have already run" means the opposite thing
/// on each path:
///
/// - `llmproxy.auth` before `llmproxy.token_limit` — both are **decode**-side.
///   The limiter buckets on `StreamInfo::auth.tenant`, which the auth filter
///   writes. Reversed, the limiter sees `None` and falls back to bucketing on
///   the client's `authorization` header — which is exactly the spoofable key
///   the auth filter exists to remove, so the reversed order is a **security** downgrade, not a
///   cosmetic one.
/// - `llmproxy.token_limit` before `llmproxy.usage` — the limiter's *record*
///   is **encode**-side, and reads the usage the usage filter wrote. Because
///   encode order is reversed, "the usage filter has already run" means it is
///   **later** in config order. Reversed, every request records **zero**
///   tokens against its budget: the limit exists and never fires.
///
/// # Two more decode-side rules for `llmproxy.model_authz`
///
/// `llmproxy.model_authz` needs BOTH the tenant `llmproxy.auth` resolves
/// (`StreamInfo::auth.tenant`) and the model `llmproxy.body_rewrite`
/// extracts (`StreamInfo::requested_model`). All three are decode-side, so
/// both required orderings run the same direction as the auth/token_limit
/// rule above: `llmproxy.auth` and `llmproxy.body_rewrite` must each come
/// BEFORE `llmproxy.model_authz`. Reversed, the authz filter reads `None` for
/// whichever fact came from the reordered filter and — per its fail-closed
/// design (`proxy_filters::model_authz_filter`'s module doc) — refuses EVERY
/// request rather than silently admitting one it can't check; still a config
/// error, because "authorization now refuses 100% of traffic" is exactly the
/// kind of surprise AGENTS.md invariant 1 exists to catch at load time instead of
/// in production.
///
/// # `llmproxy.spend_limit` gets the SAME two-rule
/// shape as `llmproxy.token_limit`, for the identical reason
///
/// `llmproxy.spend_limit` is decode-check + encode-record, exactly like
/// `llmproxy.token_limit` (see that filter's module doc's "Retrospective
/// enforcement" section) — so it needs the same two orderings, in the same
/// two directions:
///
/// - `llmproxy.auth` BEFORE `llmproxy.spend_limit` (decode-side): the spend
///   filter's decode check buckets on `StreamInfo::auth.tenant`, which the
///   auth filter writes; decode callbacks run in config order. Reversed, the
///   spend filter sees no tenant on every request and treats every one as
///   unlimited (see `proxy_filters::spend_limit_filter`'s "no tenant ->
///   admit" section) — a ceiling that silently never fires, the money
///   analogue of the token-limiter's spoofable-credential downgrade.
/// - `llmproxy.spend_limit` BEFORE `llmproxy.usage` (encode-side): the spend
///   filter's `record` runs on the ENCODE path, which is REVERSE config
///   order, so "the usage filter has already run" means "the usage filter is
///   LATER in config order" — exactly `token_limit`'s own usage-ordering rule
///   restated for money. Reversed, `StreamInfo::llm.usage` reads `None`
///   forever and every request is priced as if it cost nothing, so a
///   configured ceiling can never be reached no matter how much a tenant
///   actually spends.
///
/// # `llmproxy.model_resolver` sits between extraction and authorization
///
/// The resolver reads the tenant `llmproxy.auth` writes and the model
/// `llmproxy.body_rewrite` publishes, and `llmproxy.model_authz` must check
/// the model it resolved. All three are decode-side, so `llmproxy.auth` and
/// `llmproxy.body_rewrite` come BEFORE the resolver, and the resolver comes
/// BEFORE `llmproxy.model_authz`. Reversed, the resolver would see no tenant
/// and give every tenant the default, or see no model and never resolve, or
/// the authz filter would refuse `auto` as an ungranted model name. The
/// resolver without `llmproxy.body_rewrite` anywhere in the chain is also an
/// error: it would never see a model, and `auto` would reach the provider.
///
/// Both rules are stated at their own call sites too
/// (`token_limit_filter`'s, `model_authz_filter`'s, and
/// `spend_limit_filter`'s module docs); this function is the enforcement.
fn check_lane_h_filter_order(
    http_filters: &[HttpFilterSpec],
    path: &str,
) -> Result<(), ConfigError> {
    // A duplicate exact type URL is impossible (`FilterRegistry` keys on it),
    // but one legacy TokenLimit alias stays registered for a release.
    // A chain may therefore contain one old and one canonical limiter, so
    // each ordering rule must inspect EVERY matching position rather than
    // only the first and accidentally leave one unprotected.
    let indices_of = |type_urls: &[&str]| {
        http_filters
            .iter()
            .enumerate()
            .filter_map(|(index, f)| {
                type_urls
                    .iter()
                    .any(|type_url| f.type_url == *type_url)
                    .then_some(index)
            })
            .collect::<Vec<_>>()
    };

    let rules = [
        (
            AUTH_FILTER_TYPE,
            "llmproxy.auth",
            TOKEN_LIMIT_FILTER_TYPE,
            "llmproxy.token_limit",
            "the token limiter buckets on the tenant the auth filter resolves, and decode \
             callbacks run in config order; with this order reversed the limiter silently \
             falls back to bucketing on the client-supplied `authorization` header, which \
             a caller can change to get a fresh quota",
        ),
        (
            TOKEN_LIMIT_FILTER_TYPE,
            "llmproxy.token_limit",
            USAGE_FILTER_TYPE,
            "llmproxy.usage",
            "the token limiter records usage on the ENCODE path, which runs in REVERSE \
             config order, so the usage filter must come LATER in config order for its \
             report to exist by then; with this order reversed every request silently \
             records zero tokens against its budget",
        ),
        (
            AUTH_FILTER_TYPE,
            "llmproxy.auth",
            MODEL_AUTHZ_FILTER_TYPE,
            "llmproxy.model_authz",
            "the model-authz filter reads the tenant the auth filter resolves from \
             StreamInfo::auth.tenant, and decode callbacks run in config order; with this \
             order reversed the authz filter would see no tenant and refuse every request",
        ),
        (
            BODY_REWRITE_FILTER_TYPE,
            "llmproxy.body_rewrite",
            MODEL_AUTHZ_FILTER_TYPE,
            "llmproxy.model_authz",
            "the model-authz filter reads the requested model body_rewrite publishes onto \
             StreamInfo::requested_model, and decode callbacks run in config order; with \
             this order reversed the authz filter would see no model and refuse every \
             request",
        ),
        (
            AUTH_FILTER_TYPE,
            "llmproxy.auth",
            MODEL_RESOLVER_FILTER_TYPE,
            "llmproxy.model_resolver",
            "the model resolver picks a model from the tenant the auth filter resolves, \
             and decode callbacks run in config order; with this order reversed every \
             tenant would silently get the default model",
        ),
        (
            BODY_REWRITE_FILTER_TYPE,
            "llmproxy.body_rewrite",
            MODEL_RESOLVER_FILTER_TYPE,
            "llmproxy.model_resolver",
            "the model resolver reads the requested model body_rewrite publishes onto \
             StreamInfo::requested_model, and decode callbacks run in config order; with \
             this order reversed `auto` would never be resolved and would reach the provider",
        ),
        (
            MODEL_RESOLVER_FILTER_TYPE,
            "llmproxy.model_resolver",
            MODEL_AUTHZ_FILTER_TYPE,
            "llmproxy.model_authz",
            "the model-authz filter must check the model the resolver chose, and decode \
             callbacks run in config order; with this order reversed the authz filter \
             would check the literal name `auto` instead",
        ),
        (
            AUTH_FILTER_TYPE,
            "llmproxy.auth",
            SPEND_LIMIT_FILTER_TYPE,
            "llmproxy.spend_limit",
            "the spend limiter buckets on the tenant the auth filter resolves, and decode \
             callbacks run in config order; with this order reversed the spend filter would \
             see no tenant on every request and treat every one as unlimited, so a \
             configured ceiling would silently never fire",
        ),
        (
            SPEND_LIMIT_FILTER_TYPE,
            "llmproxy.spend_limit",
            USAGE_FILTER_TYPE,
            "llmproxy.usage",
            "the spend limiter records cost on the ENCODE path, which runs in REVERSE \
             config order, so the usage filter must come LATER in config order for its \
             report to exist by then; with this order reversed every request would be \
             priced as free and a configured ceiling could never be reached",
        ),
    ];

    if let Some(resolver) = indices_of(&[MODEL_RESOLVER_FILTER_TYPE]).first() {
        if indices_of(&[BODY_REWRITE_FILTER_TYPE, LEGACY_BODY_REWRITE_FILTER_TYPE]).is_empty() {
            return Err(invalid(
                format!("{path}.http_filters[{resolver}]"),
                "`llmproxy.model_resolver` requires `llmproxy.body_rewrite` earlier in the \
                 same chain: the resolver reads the model body_rewrite extracts, and without \
                 it `auto` would never be resolved and would reach the provider",
            ));
        }
    }

    for (first_type, first_name, second_type, second_name, reason) in rules {
        // A rule only applies when BOTH filters are present -- either one
        // alone is a perfectly ordinary chain.
        let first_types = if first_type == TOKEN_LIMIT_FILTER_TYPE {
            &[TOKEN_LIMIT_FILTER_TYPE, LEGACY_TOKEN_LIMIT_FILTER_TYPE][..]
        } else if first_type == USAGE_FILTER_TYPE {
            &[USAGE_FILTER_TYPE, LEGACY_USAGE_FILTER_TYPE][..]
        } else if first_type == BODY_REWRITE_FILTER_TYPE {
            &[BODY_REWRITE_FILTER_TYPE, LEGACY_BODY_REWRITE_FILTER_TYPE][..]
        } else {
            &[first_type][..]
        };
        let second_types = if second_type == TOKEN_LIMIT_FILTER_TYPE {
            &[TOKEN_LIMIT_FILTER_TYPE, LEGACY_TOKEN_LIMIT_FILTER_TYPE][..]
        } else if second_type == USAGE_FILTER_TYPE {
            &[USAGE_FILTER_TYPE, LEGACY_USAGE_FILTER_TYPE][..]
        } else if second_type == BODY_REWRITE_FILTER_TYPE {
            &[BODY_REWRITE_FILTER_TYPE, LEGACY_BODY_REWRITE_FILTER_TYPE][..]
        } else {
            &[second_type][..]
        };
        for first in indices_of(first_types) {
            for second in indices_of(second_types) {
                if first > second {
                    return Err(invalid(
                        format!("{path}.http_filters[{first}]"),
                        format!(
                            "`{first_name}` must be configured BEFORE `{second_name}` \
                             (currently at index {second}): {reason}"
                        ),
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Rejects a duplicate HCM `stat_prefix` among chains that
/// configure `llmproxy.auth`, across this ENTIRE listener (`seen` is shared
/// by every listener the caller processes, not reset per-listener -- two
/// different listeners each configuring `llmproxy.auth` under the same
/// `stat_prefix` collide exactly the same as two chains on one listener).
///
/// Deliberately narrow (addressing follows Envoy):
/// Envoy tolerates a duplicate `stat_prefix` everywhere (it merges stats),
/// and a duplicate among chains that register NO admin-addressable
/// singleton must stay legal -- e.g. two `llmproxy.token_limit`-only chains
/// sharing a name is fine, because nothing ever looks one up by that name.
/// `llmproxy.auth` is the only filter an admin endpoint addresses by name
/// today (`SharedFactoryState::get_by_name`, `proxy-admin`'s
/// `/chains/{stat_prefix}/...`); a chain that never registers one has no
/// addressing collision to have. Walks both `filter_chains` and
/// `default_filter_chain` -- either can carry an HCM.
fn check_admin_addressable_stat_prefixes(
    listener: &ListenerConfig,
    path: &str,
    seen: &mut std::collections::HashMap<String, String>,
) -> Result<(), ConfigError> {
    for (i, fc) in listener.filter_chains.iter().enumerate() {
        check_filter_chain_stat_prefix(fc, &format!("{path}.filter_chains[{i}]"), seen)?;
    }
    if let Some(fc) = &listener.default_filter_chain {
        check_filter_chain_stat_prefix(fc, &format!("{path}.default_filter_chain"), seen)?;
    }
    Ok(())
}

/// One filter chain's half of [`check_admin_addressable_stat_prefixes`]:
/// finds this chain's HCM (if it has one -- a `TcpProxy`-terminated chain
/// does not), and if it configures `llmproxy.auth`, records or rejects its
/// `stat_prefix` against every chain already seen.
fn check_filter_chain_stat_prefix(
    fc: &FilterChainSpec,
    path: &str,
    seen: &mut std::collections::HashMap<String, String>,
) -> Result<(), ConfigError> {
    for (k, filter) in fc.filters.iter().enumerate() {
        let NetworkFilterSpec::HttpConnectionManager(hcm) = filter else {
            continue;
        };
        let configures_auth = hcm
            .http_filters
            .iter()
            .any(|f| f.type_url == AUTH_FILTER_TYPE);
        if !configures_auth {
            continue;
        }
        let stat_prefix_path = format!("{path}.filters[{k}].typed_config.stat_prefix");
        if let Some(first_path) = seen.get(&hcm.stat_prefix) {
            return Err(invalid(
                stat_prefix_path,
                format!(
                    "duplicate stat_prefix `{}` (already used at `{first_path}`): both chains \
                     configure llmproxy.auth, so admin addressing \
                     (`/chains/{{stat_prefix}}/...`) and persisted spend rows could not tell \
                     them apart -- a duplicate stat_prefix among chains that DON'T configure \
                     llmproxy.auth stays legal, exactly as in Envoy",
                    hcm.stat_prefix
                ),
            ));
        }
        seen.insert(hcm.stat_prefix.clone(), stat_prefix_path);
    }
    Ok(())
}

// ------------------------------------------------------------ access log --

fn convert_access_logs(
    entries: &[accesslog_v3::AccessLog],
    path: &str,
) -> Result<Vec<AccessLogIR>, ConfigError> {
    entries
        .iter()
        .enumerate()
        .map(|(i, e)| convert_access_log(e, &format!("{path}[{i}]")))
        .collect()
}

fn convert_access_log(e: &accesslog_v3::AccessLog, path: &str) -> Result<AccessLogIR, ConfigError> {
    use accesslog_v3::access_log::ConfigType;
    let any = match &e.config_type {
        Some(ConfigType::TypedConfig(any)) => any,
        None => return Err(invalid(path, "access log requires typed_config")),
    };
    let filter = e
        .filter
        .as_ref()
        .map(|f| convert_access_log_filter(f, &format!("{path}.filter")))
        .transpose()?;

    let cfg_path = format!("{path}.typed_config");
    let (sink, sfs) = match type_name(any) {
        FILE_ACCESS_LOG_TYPE => {
            let file: access_log_file_v3::FileAccessLog = decode_any(any, &cfg_path)?;
            if file.path.is_empty() {
                return Err(invalid(format!("{cfg_path}.path"), "path is required"));
            }
            use access_log_file_v3::file_access_log::AccessLogFormat as F;
            let sfs = match file.access_log_format {
                Some(F::LogFormat(sfs)) => Some(sfs),
                // AGENTS.md invariant 1: the deprecated `format`/`json_format`/
                // `typed_json_format` oneof members aren't in this message's
                // `allowed_fields` entry, so the surface check already
                // rejects them before typed conversion runs; this arm is
                // unreachable in practice but kept explicit rather than
                // `unreachable!()` so a future allowlist change fails loudly
                // here too, not with a panic.
                Some(_) => {
                    return Err(unsupported(
                        format!("{cfg_path}.access_log_format"),
                        "only `log_format` is implemented for the file access logger",
                    ))
                }
                None => None,
            };
            (
                AccessLogSink::File {
                    path: file.path.clone(),
                },
                sfs,
            )
        }
        STDOUT_ACCESS_LOG_TYPE => {
            let stdout: access_log_stream_v3::StdoutAccessLog = decode_any(any, &cfg_path)?;
            use access_log_stream_v3::stdout_access_log::AccessLogFormat as F;
            let sfs = stdout.access_log_format.map(|F::LogFormat(sfs)| sfs);
            (AccessLogSink::Stdout, sfs)
        }
        STDERR_ACCESS_LOG_TYPE => {
            let stderr: access_log_stream_v3::StderrAccessLog = decode_any(any, &cfg_path)?;
            use access_log_stream_v3::stderr_access_log::AccessLogFormat as F;
            let sfs = stderr.access_log_format.map(|F::LogFormat(sfs)| sfs);
            (AccessLogSink::Stderr, sfs)
        }
        _ => {
            return Err(ConfigError::UnknownTypeUrl {
                field_path: cfg_path,
                type_url: any.type_url.clone(),
            })
        }
    };

    let format = match sfs {
        Some(sfs) => convert_substitution_format(&sfs, &cfg_path)?,
        // Envoy default when a sink omits `log_format`.
        None => AccessLogFormat::Text(parse_fmt(DEFAULT_ACCESS_LOG_FORMAT, &cfg_path)?),
    };

    Ok(AccessLogIR {
        sink,
        format,
        filter,
    })
}

fn convert_substitution_format(
    sfs: &core_v3::SubstitutionFormatString,
    path: &str,
) -> Result<AccessLogFormat, ConfigError> {
    use core_v3::substitution_format_string::Format;
    match &sfs.format {
        Some(Format::TextFormat(s)) => {
            Ok(AccessLogFormat::Text(parse_fmt(s, &format!("{path}.text_format"))?))
        }
        Some(Format::JsonFormat(strct)) => {
            let fields_path = format!("{path}.json_format");
            let mut fields = Vec::with_capacity(strct.fields.len());
            for (key, value) in &strct.fields {
                let value_path = format!("{fields_path}.{key}");
                let s = match &value.kind {
                    Some(prost_types::value::Kind::StringValue(s)) => s,
                    _ => {
                        return Err(unsupported(
                            value_path,
                            "json_format values must be strings (command-operator format \
                             strings); non-string JSON literals are not implemented",
                        ))
                    }
                };
                fields.push((key.clone(), parse_fmt(s, &value_path)?));
            }
            Ok(AccessLogFormat::Json(fields))
        }
        // `text_format_source` (field 5) isn't in `SubstitutionFormatString`'s
        // `allowed_fields` entry, so this is unreachable via the surface
        // check for the same reason as the file-logger arm above.
        Some(Format::TextFormatSource(_)) => Err(unsupported(
            format!("{path}.text_format_source"),
            "text_format_source (DataSource-based format strings) is not implemented; use text_format",
        )),
        None => Err(invalid(
            path,
            "SubstitutionFormatString requires text_format or json_format",
        )),
    }
}

/// Parse a format string, wrapping the formatter's own parse error (which
/// knows nothing about proto field paths — AGENTS.md invariant 2 keeps that
/// knowledge in `proxy-config`) into a [`ConfigError`] naming the field.
fn parse_fmt(s: &str, path: &str) -> Result<FormatString, ConfigError> {
    parse_format(s).map_err(|e| unsupported(path, e.to_string()))
}

fn convert_access_log_filter(
    f: &accesslog_v3::AccessLogFilter,
    path: &str,
) -> Result<AccessLogFilterIR, ConfigError> {
    use accesslog_v3::access_log_filter::FilterSpecifier;
    match &f.filter_specifier {
        Some(FilterSpecifier::StatusCodeFilter(scf)) => {
            let comparison = scf.comparison.as_ref().ok_or_else(|| {
                invalid(
                    format!("{path}.status_code_filter.comparison"),
                    "comparison is required",
                )
            })?;
            let op = convert_comparison_op(
                comparison.op,
                &format!("{path}.status_code_filter.comparison.op"),
            )?;
            let value_path = format!("{path}.status_code_filter.comparison.value");
            let value = comparison
                .value
                .as_ref()
                .ok_or_else(|| invalid(&value_path, "value is required"))?
                .default_value;
            Ok(AccessLogFilterIR::StatusCode { op, value })
        }
        Some(FilterSpecifier::ResponseFlagFilter(rff)) => {
            let flags_path = format!("{path}.response_flag_filter.flags");
            let flags = rff
                .flags
                .iter()
                .map(|code| {
                    ResponseFlag::from_code(code).ok_or_else(|| {
                        unsupported(
                            &flags_path,
                            format!("response flag `{code}` is not implemented"),
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(AccessLogFilterIR::ResponseFlag(flags))
        }
        Some(other) => Err(unsupported(
            path,
            format!(
                "access log filter `{}` is not implemented; only status_code_filter and \
                 response_flag_filter are supported",
                access_log_filter_kind(other)
            ),
        )),
        None => Err(invalid(path, "filter requires a filter_specifier")),
    }
}

fn access_log_filter_kind(f: &accesslog_v3::access_log_filter::FilterSpecifier) -> &'static str {
    use accesslog_v3::access_log_filter::FilterSpecifier;
    match f {
        FilterSpecifier::StatusCodeFilter(_) => "status_code_filter",
        FilterSpecifier::DurationFilter(_) => "duration_filter",
        FilterSpecifier::NotHealthCheckFilter(_) => "not_health_check_filter",
        FilterSpecifier::TraceableFilter(_) => "traceable_filter",
        FilterSpecifier::RuntimeFilter(_) => "runtime_filter",
        FilterSpecifier::AndFilter(_) => "and_filter",
        FilterSpecifier::OrFilter(_) => "or_filter",
        FilterSpecifier::HeaderFilter(_) => "header_filter",
        FilterSpecifier::ResponseFlagFilter(_) => "response_flag_filter",
        FilterSpecifier::GrpcStatusFilter(_) => "grpc_status_filter",
        FilterSpecifier::ExtensionFilter(_) => "extension_filter",
        FilterSpecifier::MetadataFilter(_) => "metadata_filter",
        FilterSpecifier::LogTypeFilter(_) => "log_type_filter",
    }
}

fn convert_comparison_op(op: i32, path: &str) -> Result<ComparisonOp, ConfigError> {
    use accesslog_v3::comparison_filter::Op;
    match Op::try_from(op) {
        Ok(Op::Eq) => Ok(ComparisonOp::Eq),
        Ok(Op::Ge) => Ok(ComparisonOp::Ge),
        Ok(Op::Le) => Ok(ComparisonOp::Le),
        Ok(Op::Ne) => Ok(ComparisonOp::Ne),
        Err(_) => Err(invalid(path, format!("unknown comparison op `{op}`"))),
    }
}

fn convert_downstream_tls(
    ts: &core_v3::TransportSocket,
    path: &str,
) -> Result<DownstreamTlsSpec, ConfigError> {
    use core_v3::transport_socket::ConfigType;
    let any = match &ts.config_type {
        Some(ConfigType::TypedConfig(any)) => any,
        None => return Err(invalid(path, "transport_socket requires typed_config")),
    };
    let cfg_path = format!("{path}.typed_config");
    if type_name(any) != DOWNSTREAM_TLS_TYPE {
        return Err(ConfigError::UnknownTypeUrl {
            field_path: cfg_path,
            type_url: any.type_url.clone(),
        });
    }
    let ctx: tls_v3::DownstreamTlsContext = decode_any(any, &cfg_path)?;
    let common = ctx
        .common_tls_context
        .as_ref()
        .ok_or_else(|| invalid(&cfg_path, "common_tls_context is required"))?;
    let common_path = format!("{cfg_path}.common_tls_context");

    let params = convert_tls_params(
        common.tls_params.as_ref(),
        &format!("{common_path}.tls_params"),
        true,
    )?;
    let tls_certificates_path = format!("{common_path}.tls_certificates");
    let certificates = if common.tls_certificates.is_empty() {
        Vec::new()
    } else {
        convert_downstream_certificates(&common.tls_certificates, &tls_certificates_path)?
    };
    let sds_path = format!("{common_path}.tls_certificate_sds_secret_configs");
    let certificate_sds_names =
        convert_certificate_sds_configs(&common.tls_certificate_sds_secret_configs, &sds_path)?;

    // Divergence #5 (internal-docs/envoy-divergences.md): Envoy's own proto
    // comment says `tls_certificate_sds_secret_configs` "is ignored" when
    // `tls_certificates` is set. AGENTS.md invariant 1 forbids silently ignoring a
    // set field, so we reject the mixed case by path instead.
    match (certificates.is_empty(), certificate_sds_names.is_empty()) {
        (false, false) => {
            return Err(invalid(
                sds_path,
                "tls_certificates is also set; exactly one of tls_certificates and \
                 tls_certificate_sds_secret_configs may be set",
            ))
        }
        (true, true) => {
            return Err(invalid(
                tls_certificates_path,
                "either tls_certificates or tls_certificate_sds_secret_configs must be set",
            ))
        }
        _ => {}
    }

    let (validation, validation_sds_name) = convert_validation_context(common, &common_path)?;

    let require_client_certificate = ctx.require_client_certificate.unwrap_or(false);
    if require_client_certificate && validation.is_none() && validation_sds_name.is_none() {
        return Err(invalid(
            format!("{cfg_path}.require_client_certificate"),
            "require_client_certificate requires a validation_context or \
             validation_context_sds_secret_config",
        ));
    }

    // Rust note: `session_ticket_keys_type` is a proto oneof, so its Rust
    // shape is `Option<enum>` — one variant per oneof member. Only the
    // stateless-resumption bool is supported; the other members are secret
    // material we don't handle yet.
    use tls_v3::downstream_tls_context::SessionTicketKeysType;
    let disable_stateless_session_resumption = match &ctx.session_ticket_keys_type {
        None => false,
        Some(SessionTicketKeysType::DisableStatelessSessionResumption(b)) => *b,
        Some(SessionTicketKeysType::SessionTicketKeys(_)) => {
            return Err(unsupported(
                format!("{cfg_path}.session_ticket_keys"),
                "explicit session ticket keys are not implemented yet",
            ))
        }
        Some(SessionTicketKeysType::SessionTicketKeysSdsSecretConfig(_)) => {
            return Err(unsupported(
                format!("{cfg_path}.session_ticket_keys_sds_secret_config"),
                "SDS-delivered session ticket keys are not implemented yet",
            ))
        }
    };

    Ok(DownstreamTlsSpec {
        certificates,
        certificate_sds_names,
        params,
        alpn_protocols: common.alpn_protocols.clone(),
        validation,
        validation_sds_name,
        require_client_certificate,
        disable_stateless_session_resumption,
    })
}

/// Shared `TlsParameters` -> IR conversion. `downstream` picks Envoy's
/// direction-dependent `TLS_AUTO` maximum-version default (v1.38: "By
/// default, it's TLSv1_2 for clients and TLSv1_3 for servers").
fn convert_tls_params(
    tp: Option<&tls_v3::TlsParameters>,
    path: &str,
    downstream: bool,
) -> Result<TlsParametersIR, ConfigError> {
    // Rust note: an unset `TlsParameters` is equivalent to one with every
    // field at its proto3 default (0 / empty), so we can normalize `None`
    // into the same defaults instead of duplicating the "no params" case.
    let empty = tls_v3::TlsParameters::default();
    let tp = tp.unwrap_or(&empty);

    let min_version = convert_tls_version(
        tp.tls_minimum_protocol_version,
        &format!("{path}.tls_minimum_protocol_version"),
        TlsVersion::V1_2,
    )?;
    let max_default = if downstream {
        TlsVersion::V1_3
    } else {
        TlsVersion::V1_2
    };
    let max_version = convert_tls_version(
        tp.tls_maximum_protocol_version,
        &format!("{path}.tls_maximum_protocol_version"),
        max_default,
    )?;
    if min_version > max_version {
        return Err(invalid(
            path,
            "tls_minimum_protocol_version must be <= tls_maximum_protocol_version",
        ));
    }

    let cipher_suites = convert_cipher_suites(&tp.cipher_suites, &format!("{path}.cipher_suites"))?;
    let ecdh_curves = convert_ecdh_curves(&tp.ecdh_curves, &format!("{path}.ecdh_curves"))?;

    Ok(TlsParametersIR {
        min_version,
        max_version,
        cipher_suites,
        ecdh_curves,
    })
}

fn convert_tls_version(
    version: i32,
    path: &str,
    auto_default: TlsVersion,
) -> Result<TlsVersion, ConfigError> {
    use tls_v3::tls_parameters::TlsProtocol;
    match TlsProtocol::try_from(version) {
        Ok(TlsProtocol::TlsAuto) => Ok(auto_default),
        Ok(TlsProtocol::TlSv12) => Ok(TlsVersion::V1_2),
        Ok(TlsProtocol::TlSv13) => Ok(TlsVersion::V1_3),
        Ok(TlsProtocol::TlSv10) => Err(unsupported(
            path,
            "TLSv1.0 is not supported; rustls does not implement TLS versions below 1.2",
        )),
        Ok(TlsProtocol::TlSv11) => Err(unsupported(
            path,
            "TLSv1.1 is not supported; rustls does not implement TLS versions below 1.2",
        )),
        Err(_) => Err(invalid(path, "unknown TLS protocol version enum value")),
    }
}

/// The six TLS 1.2 ECDHE-GCM/CHACHA20 suites rustls implements, keyed by
/// their BoringSSL/Envoy names. TLS 1.3 suites are fixed in both Envoy and
/// rustls, so they are never configurable here.
fn convert_cipher_suites(names: &[String], path: &str) -> Result<Vec<TlsCipherSuite>, ConfigError> {
    let mut out = Vec::with_capacity(names.len());
    let mut unknown = Vec::new();
    for name in names {
        if name.starts_with('[') {
            return Err(unsupported(
                path,
                "BoringSSL equal-preference groups are not supported; list suites individually",
            ));
        }
        match name.as_str() {
            "ECDHE-ECDSA-AES128-GCM-SHA256" => out.push(TlsCipherSuite::EcdheEcdsaAes128GcmSha256),
            "ECDHE-RSA-AES128-GCM-SHA256" => out.push(TlsCipherSuite::EcdheRsaAes128GcmSha256),
            "ECDHE-ECDSA-AES256-GCM-SHA384" => out.push(TlsCipherSuite::EcdheEcdsaAes256GcmSha384),
            "ECDHE-RSA-AES256-GCM-SHA384" => out.push(TlsCipherSuite::EcdheRsaAes256GcmSha384),
            "ECDHE-ECDSA-CHACHA20-POLY1305" => out.push(TlsCipherSuite::EcdheEcdsaChacha20Poly1305),
            "ECDHE-RSA-CHACHA20-POLY1305" => out.push(TlsCipherSuite::EcdheRsaChacha20Poly1305),
            _ => unknown.push(name.clone()),
        }
    }
    if !unknown.is_empty() {
        return Err(unsupported(
            path,
            format!(
                "unsupported cipher suite(s): {}; only ECDHE-ECDSA-AES128-GCM-SHA256, \
                 ECDHE-RSA-AES128-GCM-SHA256, ECDHE-ECDSA-AES256-GCM-SHA384, \
                 ECDHE-RSA-AES256-GCM-SHA384, ECDHE-ECDSA-CHACHA20-POLY1305, and \
                 ECDHE-RSA-CHACHA20-POLY1305 are configurable (the only TLS 1.2 suites \
                 rustls implements); TLS 1.3 suites are fixed, same as Envoy/BoringSSL",
                unknown.join(", ")
            ),
        ));
    }
    Ok(out)
}

fn convert_ecdh_curves(names: &[String], path: &str) -> Result<Vec<TlsEcdhCurve>, ConfigError> {
    let mut out = Vec::with_capacity(names.len());
    let mut unknown = Vec::new();
    for name in names {
        match name.as_str() {
            "X25519" => out.push(TlsEcdhCurve::X25519),
            "P-256" => out.push(TlsEcdhCurve::P256),
            "P-384" => out.push(TlsEcdhCurve::P384),
            _ => unknown.push(name.clone()),
        }
    }
    if !unknown.is_empty() {
        return Err(unsupported(
            path,
            format!(
                "unsupported ECDH curve(s): {}; only X25519, P-256, P-384 are configurable",
                unknown.join(", ")
            ),
        ));
    }
    Ok(out)
}

fn convert_tls_certificate(
    cert: &tls_v3::TlsCertificate,
    path: &str,
) -> Result<TlsCertificateIR, ConfigError> {
    let cert_chain = convert_data_source(
        cert.certificate_chain.as_ref(),
        &format!("{path}.certificate_chain"),
    )?;
    let private_key =
        convert_data_source(cert.private_key.as_ref(), &format!("{path}.private_key"))?;
    Ok(TlsCertificateIR {
        cert_chain,
        private_key,
    })
}

/// Downstream: 1 or 2 certificates (one per key type — RSA and ECDSA — like
/// Envoy/BoringSSL). Which entry is which key type is resolved when the
/// rustls socket loads the keys, not here.
///
/// Callers only invoke this for a non-empty slice; the "must be non-empty"
/// half of the invariant lives in `convert_downstream_tls`, alongside the
/// `tls_certificate_sds_secret_configs` mutual-exclusion check it shares a
/// path with.
fn convert_downstream_certificates(
    certs: &[tls_v3::TlsCertificate],
    path: &str,
) -> Result<Vec<TlsCertificateIR>, ConfigError> {
    if certs.len() > 2 {
        return Err(invalid(
            path,
            "Envoy allows at most one certificate per key type (RSA, ECDSA)",
        ));
    }
    certs
        .iter()
        .enumerate()
        .map(|(i, c)| convert_tls_certificate(c, &format!("{path}[{i}]")))
        .collect()
}

/// `tls_certificate_sds_secret_configs` -> secret names the SDS subscription
/// will request. Each entry must carry an ADS
/// `sds_config`; a name-only entry means "look this up in
/// `static_resources.secrets`", which is refused below rather than resolved
/// to nothing -- see the doc on `DownstreamTlsSpec::certificate_sds_names`.
fn convert_certificate_sds_configs(
    configs: &[tls_v3::SdsSecretConfig],
    path: &str,
) -> Result<Vec<SecretName>, ConfigError> {
    if configs.len() > 2 {
        return Err(invalid(
            path,
            "Envoy allows at most one certificate per key type (RSA, ECDSA)",
        ));
    }
    // Rust note: collecting into `Vec` (not `HashSet`) preserves declaration
    // order, which the IR doc promises callers -- the duplicate check below
    // is a linear `contains` scan instead of a set insert for that reason.
    let mut names: Vec<SecretName> = Vec::with_capacity(configs.len());
    for (i, cfg) in configs.iter().enumerate() {
        let entry_path = format!("{path}[{i}]");
        if cfg.name.is_empty() {
            return Err(invalid(
                format!("{entry_path}.name"),
                "an SDS secret config must name the secret it subscribes to",
            ));
        }
        if names.contains(&cfg.name) {
            return Err(invalid(
                path,
                format!("`{}` is named more than once in the same chain", cfg.name),
            ));
        }
        let sds_config_path = format!("{entry_path}.sds_config");
        let source = check_ads_source(cfg.sds_config.as_ref(), &sds_config_path)?;
        if source.is_none() {
            return Err(unsupported(
                sds_config_path,
                "a name-only SdsSecretConfig resolves against static_resources.secrets, \
                 whose TlsSecret is still a stub carrying only a name, so there is nothing \
                 to resolve to yet",
            ));
        }
        if source
            .as_ref()
            .is_some_and(|source| source.initial_fetch_timeout.is_some())
        {
            return Err(unsupported(
                format!("{entry_path}.sds_config.initial_fetch_timeout"),
                "SDS initial_fetch_timeout is not implemented",
            ));
        }
        names.push(cfg.name.clone());
    }
    Ok(names)
}

/// Upstream: at most one client (mTLS) certificate.
fn convert_upstream_certificate(
    certs: &[tls_v3::TlsCertificate],
    path: &str,
) -> Result<Option<TlsCertificateIR>, ConfigError> {
    match certs {
        [] => Ok(None),
        [cert] => Ok(Some(convert_tls_certificate(
            cert,
            &format!("{path}[0]"),
        )?)),
        _ => Err(invalid(
            path,
            "at most one client certificate is supported (one per key type is a downstream-only concept)",
        )),
    }
}

// --------------------------------------------------------- dynamic (xDS) --

/// Lower bootstrap `dynamic_resources` into [`AdsConfig`].
///
/// **This widens a deliberate refusal, it does not fix a silent drop.** Before
/// this increment `Bootstrap`'s allowed-field list named only
/// `node`/`admin`/`static_resources`, so a config carrying `dynamic_resources`
/// failed strict-mode validation by name -- AGENTS.md invariant 1 working correctly.
///
/// v1 accepts a narrow surface and refuses everything else with its full
/// dotted path: `api_type: GRPC`, `transport_api_version: V3`, and exactly one
/// `grpc_services` entry using `envoy_grpc` when an ADS source is selected.
/// Per-type LDS/CDS filesystem sources are also supported; `eds_config` needs
/// an IR discovery variant that does not exist.
fn convert_dynamic_resources(b: &Bootstrap, path: &str) -> Result<Option<AdsConfig>, ConfigError> {
    let Some(dr) = &b.dynamic_resources else {
        return Ok(None);
    };

    // `xdstp://` resource locators are upstream-hidden and unimplemented.
    if !dr.lds_resources_locator.is_empty() {
        return Err(unsupported(
            format!("{path}.lds_resources_locator"),
            "xdstp:// resource locators are not implemented",
        ));
    }
    if !dr.cds_resources_locator.is_empty() {
        return Err(unsupported(
            format!("{path}.cds_resources_locator"),
            "xdstp:// resource locators are not implemented",
        ));
    }

    let Some(api) = &dr.ads_config else {
        // A per-type ConfigSource without an ads_config is a separate
        // transport (its own gRPC stream, or REST polling), not ADS.
        let lds_source = check_source(dr.lds_config.as_ref(), &format!("{path}.lds_config"))?;
        let cds_source = check_source(dr.cds_config.as_ref(), &format!("{path}.cds_config"))?;
        if lds_source
            .as_ref()
            .is_some_and(|source| matches!(source, crate::ir::DiscoverySource::Ads))
            || cds_source
                .as_ref()
                .is_some_and(|source| matches!(source, crate::ir::DiscoverySource::Ads))
        {
            return Err(unsupported(
                format!("{path}.ads_config"),
                "ADS-backed sources require dynamic_resources.ads_config",
            ));
        }
        if lds_source.is_none() && cds_source.is_none() {
            return Err(unsupported(
                format!("{path}.ads_config"),
                "lds_config/cds_config are only implemented when delivered over ADS, so \
                 dynamic_resources.ads_config must be set",
            ));
        }
        return Ok(Some(AdsConfig {
            cluster: None,
            protocol: crate::ir::AdsProtocol::Sotw,
            lds: lds_source.is_some(),
            cds: cds_source.is_some(),
            initial_fetch_timeout: None,
            node: NodeIdentity::default(),
            lds_source,
            cds_source,
        }));
    };
    let api_path = format!("{path}.ads_config");

    // Per-type sources may be ADS-backed or filesystem-backed. The transport
    // is retained in the IR so runtime startup can subscribe or watch each
    // resource type independently.
    let lds_source = check_ads_source(dr.lds_config.as_ref(), &format!("{path}.lds_config"))?;
    let cds_source = check_ads_source(dr.cds_config.as_ref(), &format!("{path}.cds_config"))?;
    let lds = lds_source.is_some();
    let cds = cds_source.is_some();

    if (lds || cds)
        && !lds_source
            .as_ref()
            .is_some_and(|source| matches!(source.transport, crate::ir::DiscoverySource::Ads))
        && !cds_source
            .as_ref()
            .is_some_and(|source| matches!(source.transport, crate::ir::DiscoverySource::Ads))
    {
        return Ok(Some(AdsConfig {
            cluster: None,
            protocol: crate::ir::AdsProtocol::Sotw,
            lds,
            cds,
            initial_fetch_timeout: None,
            node: NodeIdentity::default(),
            lds_source: lds_source.map(|source| source.transport),
            cds_source: cds_source.map(|source| source.transport),
        }));
    }

    // EDS is not lowered here: the IR has no `Eds` discovery variant to lower into, and
    // inventing one here would put the warming semantics in the wrong package.
    if !lds && !cds {
        return Err(invalid(
            &api_path,
            "dynamic_resources.ads_config is set but neither lds_config nor cds_config \
             subscribes over ADS, so nothing would be requested",
        ));
    }

    let initial_fetch_timeout = match (
        lds_source
            .as_ref()
            .and_then(|source| source.initial_fetch_timeout),
        cds_source
            .as_ref()
            .and_then(|source| source.initial_fetch_timeout),
    ) {
        (Some(lds_timeout), Some(cds_timeout)) if lds_timeout != cds_timeout => {
            return Err(unsupported(
                format!("{path}.cds_config.initial_fetch_timeout"),
                "independent LDS and CDS initial_fetch_timeout values are not implemented; configure the same value for both sources",
            ));
        }
        (Some(timeout), _) | (_, Some(timeout)) => Some(timeout),
        (None, None) => None,
    };

    convert_api_config_source(
        api,
        &api_path,
        AdsSourceSelection {
            lds,
            cds,
            initial_fetch_timeout,
            lds_source: lds_source.as_ref().map(|source| source.transport.clone()),
            cds_source: cds_source.as_ref().map(|source| source.transport.clone()),
        },
        b,
    )
}

/// ADS-specific settings extracted from one per-type [`ConfigSource`].
/// `None` from [`check_ads_source`] means this resource type is not subscribed.
struct AdsSource {
    initial_fetch_timeout: Option<StdDuration>,
    transport: crate::ir::DiscoverySource,
}

struct AdsSourceSelection {
    lds: bool,
    cds: bool,
    initial_fetch_timeout: Option<StdDuration>,
    lds_source: Option<crate::ir::DiscoverySource>,
    cds_source: Option<crate::ir::DiscoverySource>,
}

fn check_source(
    source: Option<&core_v3::ConfigSource>,
    path: &str,
) -> Result<Option<crate::ir::DiscoverySource>, ConfigError> {
    let Some(source) = source else {
        return Ok(None);
    };
    use core_v3::config_source::ConfigSourceSpecifier;
    match &source.config_source_specifier {
        Some(ConfigSourceSpecifier::Path(path_value)) => {
            if path_value.is_empty() {
                return Err(invalid(
                    format!("{path}.path_config_source.path"),
                    "path must not be empty",
                ));
            }
            if !std::path::Path::new(path_value).exists() {
                return Err(invalid(
                    format!("{path}.path_config_source.path"),
                    "path must exist at config load time",
                ));
            }
            Ok(Some(crate::ir::DiscoverySource::Filesystem(
                path_value.clone().into(),
            )))
        }
        Some(ConfigSourceSpecifier::PathConfigSource(config)) => {
            if config.path.is_empty() {
                return Err(invalid(
                    format!("{path}.path_config_source.path"),
                    "path must not be empty",
                ));
            }
            if !std::path::Path::new(&config.path).exists() {
                return Err(invalid(
                    format!("{path}.path_config_source.path"),
                    "path must exist at config load time",
                ));
            }
            Ok(Some(crate::ir::DiscoverySource::Filesystem(
                config.path.clone().into(),
            )))
        }
        Some(ConfigSourceSpecifier::Ads(_)) => Ok(Some(crate::ir::DiscoverySource::Ads)),
        Some(_) => Err(unsupported(
            format!("{path}.path_config_source"),
            "unsupported config source",
        )),
        None => Err(invalid(
            path,
            "a config source must set one of its specifier members",
        )),
    }
}

/// A per-type `ConfigSource` supports ADS and filesystem transports.
fn check_ads_source(
    source: Option<&core_v3::ConfigSource>,
    path: &str,
) -> Result<Option<AdsSource>, ConfigError> {
    use core_v3::config_source::ConfigSourceSpecifier;
    let Some(source) = source else {
        return Ok(None);
    };
    if !source.resource_api_version().eq(&core_v3::ApiVersion::V3) {
        return Err(unsupported(
            format!("{path}.resource_api_version"),
            "only the V3 xDS resource API version is implemented",
        ));
    }
    match &source.config_source_specifier {
        Some(ConfigSourceSpecifier::Ads(_)) => Ok(Some(AdsSource {
            initial_fetch_timeout: source
                .initial_fetch_timeout
                .as_ref()
                .map(|timeout| to_std_duration(timeout, &format!("{path}.initial_fetch_timeout")))
                .transpose()?,
            transport: crate::ir::DiscoverySource::Ads,
        })),
        Some(ConfigSourceSpecifier::ApiConfigSource(_)) => Err(unsupported(
            format!("{path}.api_config_source"),
            "a per-type api_config_source is not implemented; use `ads` or a filesystem source",
        )),
        Some(ConfigSourceSpecifier::Path(value)) => {
            if value.is_empty() {
                return Err(invalid(
                    format!("{path}.path_config_source.path"),
                    "path must not be empty",
                ));
            }
            if !std::path::Path::new(value).exists() {
                return Err(invalid(
                    format!("{path}.path_config_source.path"),
                    "path must exist at config load time",
                ));
            }
            Ok(Some(AdsSource {
                initial_fetch_timeout: None,
                transport: crate::ir::DiscoverySource::Filesystem(value.clone().into()),
            }))
        }
        Some(ConfigSourceSpecifier::PathConfigSource(value)) => {
            if value.path.is_empty() {
                return Err(invalid(
                    format!("{path}.path_config_source.path"),
                    "path must not be empty",
                ));
            }
            if !std::path::Path::new(&value.path).exists() {
                return Err(invalid(
                    format!("{path}.path_config_source.path"),
                    "path must exist at config load time",
                ));
            }
            Ok(Some(AdsSource {
                initial_fetch_timeout: None,
                transport: crate::ir::DiscoverySource::Filesystem(value.path.clone().into()),
            }))
        }
        Some(ConfigSourceSpecifier::Self_(_)) => Err(unsupported(
            format!("{path}.self"),
            "`self` config sources are not implemented",
        )),
        None => Err(invalid(
            path,
            "a config source must set one of its specifier members",
        )),
    }
}

/// The `ApiConfigSource` half: transport, versions, and the target cluster.
fn convert_api_config_source(
    api: &core_v3::ApiConfigSource,
    path: &str,
    selection: AdsSourceSelection,
    b: &Bootstrap,
) -> Result<Option<AdsConfig>, ConfigError> {
    use core_v3::api_config_source::ApiType;

    // Rust note: prost renders a proto enum field as `i32` plus a generated
    // accessor that maps an unknown value to the default; matching on the
    // accessor keeps every named variant explicit (no `_ =>` fallthrough), so
    // adding a variant upstream is a compile error rather than a silent
    // acceptance -- AGENTS.md invariant 1 applied to enums.
    let protocol = match api.api_type() {
        ApiType::Grpc => crate::ir::AdsProtocol::Sotw,
        ApiType::DeltaGrpc => crate::ir::AdsProtocol::Delta,
        ApiType::AggregatedDeltaGrpc => {
            return Err(unsupported(
                format!("{path}.api_type"),
                "AGGREGATED_DELTA_GRPC is set implicitly by dynamic_resources.ads_config; use DELTA_GRPC",
            ));
        }
        ApiType::Rest | ApiType::DeprecatedAndUnavailableDoNotUse => {
            return Err(unsupported(
                format!("{path}.api_type"),
                "REST xDS is not implemented and is not planned; use GRPC",
            ));
        }
        ApiType::AggregatedGrpc => {
            return Err(unsupported(
                format!("{path}.api_type"),
                "AGGREGATED_GRPC is set implicitly by dynamic_resources.ads_config; use GRPC",
            ));
        }
    };

    if !api.transport_api_version().eq(&core_v3::ApiVersion::V3) {
        return Err(unsupported(
            format!("{path}.transport_api_version"),
            "only the V3 xDS transport API version is implemented",
        ));
    }

    // REST-only field; silently ignoring it would pick a different server.
    if !api.cluster_names.is_empty() {
        return Err(unsupported(
            format!("{path}.cluster_names"),
            "cluster_names is REST-only; name the ADS cluster via grpc_services[0].envoy_grpc",
        ));
    }
    if api.refresh_delay.is_some() {
        return Err(unsupported(
            format!("{path}.refresh_delay"),
            "refresh_delay is REST-only and is not honoured for gRPC ADS",
        ));
    }
    if api.request_timeout.is_some() {
        return Err(unsupported(
            format!("{path}.request_timeout"),
            "request_timeout is REST-only and is not honoured for gRPC ADS",
        ));
    }
    if api.rate_limit_settings.is_some() {
        return Err(unsupported(
            format!("{path}.rate_limit_settings"),
            "discovery-request rate limiting is not implemented",
        ));
    }
    if !api.config_validators.is_empty() {
        return Err(unsupported(
            format!("{path}.config_validators"),
            "config validator extensions are not implemented",
        ));
    }
    if api.set_node_on_first_message_only {
        return Err(unsupported(
            format!("{path}.set_node_on_first_message_only"),
            "the Node is sent on every discovery request; omitting it after the first is not \
             implemented",
        ));
    }

    if api.grpc_services.len() != 1 {
        return Err(unsupported(
            format!("{path}.grpc_services"),
            format!(
                "exactly one ADS gRPC service is implemented, found {}",
                api.grpc_services.len()
            ),
        ));
    }
    let svc_path = format!("{path}.grpc_services[0]");
    let cluster = convert_ads_grpc_service(&api.grpc_services[0], &svc_path)?;

    Ok(Some(AdsConfig {
        cluster: Some(cluster),
        protocol,
        lds: selection.lds,
        cds: selection.cds,
        initial_fetch_timeout: selection.initial_fetch_timeout,
        node: NodeIdentity {
            id: b.node.as_ref().map(|n| n.id.clone()).unwrap_or_default(),
            cluster: b
                .node
                .as_ref()
                .map(|n| n.cluster.clone())
                .unwrap_or_default(),
        },
        lds_source: selection.lds_source,
        cds_source: selection.cds_source,
    }))
}

/// Only the `envoy_grpc` target is implemented -- `google_grpc` is a whole
/// second gRPC stack with its own TLS and channel configuration.
fn convert_ads_grpc_service(svc: &core_v3::GrpcService, path: &str) -> Result<String, ConfigError> {
    use core_v3::grpc_service::TargetSpecifier;
    match &svc.target_specifier {
        Some(TargetSpecifier::EnvoyGrpc(e)) => {
            if e.cluster_name.is_empty() {
                return Err(invalid(
                    format!("{path}.envoy_grpc.cluster_name"),
                    "the ADS cluster name must not be empty",
                ));
            }
            Ok(e.cluster_name.clone())
        }
        Some(TargetSpecifier::GoogleGrpc(_)) => Err(unsupported(
            format!("{path}.google_grpc"),
            "the google_grpc client is not implemented; use envoy_grpc",
        )),
        None => Err(invalid(
            path,
            "a gRPC service must set one of its target members",
        )),
    }
}

/// Lower the static or SDS validation-context oneof. The SDS member has the
/// same ADS-only restriction as serving-certificate SDS config: a name-only
/// entry would resolve against the not-yet-implemented static secret store.
fn convert_validation_context(
    common: &tls_v3::CommonTlsContext,
    common_path: &str,
) -> Result<(Option<ValidationContextIR>, Option<SecretName>), ConfigError> {
    use tls_v3::common_tls_context::ValidationContextType;
    match &common.validation_context_type {
        None => Ok((None, None)),
        Some(ValidationContextType::ValidationContext(vc)) => Ok((
            Some(convert_validation_context_inner(
                vc,
                &format!("{common_path}.validation_context"),
            )?),
            None,
        )),
        Some(ValidationContextType::ValidationContextSdsSecretConfig(cfg)) => Ok((
            None,
            Some(convert_validation_context_sds_config(
                cfg,
                &format!("{common_path}.validation_context_sds_secret_config"),
            )?),
        )),
        Some(ValidationContextType::CombinedValidationContext(_)) => Err(unsupported(
            format!("{common_path}.combined_validation_context"),
            "combined (static + SDS) validation contexts are not implemented yet",
        )),
        Some(ValidationContextType::ValidationContextCertificateProvider(_)) => Err(unsupported(
            format!("{common_path}.validation_context_certificate_provider"),
            "certificate-provider validation contexts are not implemented",
        )),
        Some(ValidationContextType::ValidationContextCertificateProviderInstance(_)) => {
            Err(unsupported(
                format!("{common_path}.validation_context_certificate_provider_instance"),
                "certificate-provider validation contexts are not implemented",
            ))
        }
    }
}

fn convert_validation_context_sds_config(
    cfg: &tls_v3::SdsSecretConfig,
    path: &str,
) -> Result<SecretName, ConfigError> {
    if cfg.name.is_empty() {
        return Err(invalid(
            format!("{path}.name"),
            "an SDS secret config must name the secret it subscribes to",
        ));
    }
    let sds_config_path = format!("{path}.sds_config");
    let source = check_ads_source(cfg.sds_config.as_ref(), &sds_config_path)?;
    if source.is_none() {
        return Err(unsupported(
            sds_config_path,
            "a name-only SdsSecretConfig resolves against static_resources.secrets, \
             whose TlsSecret is still a stub carrying only a name, so there is nothing \
             to resolve to yet",
        ));
    }
    if source
        .as_ref()
        .is_some_and(|source| source.initial_fetch_timeout.is_some())
    {
        return Err(unsupported(
            format!("{path}.sds_config.initial_fetch_timeout"),
            "SDS initial_fetch_timeout is not implemented",
        ));
    }
    Ok(cfg.name.clone())
}

fn convert_validation_context_inner(
    vc: &tls_v3::CertificateValidationContext,
    path: &str,
) -> Result<ValidationContextIR, ConfigError> {
    let ca = match (&vc.trusted_ca, &vc.system_root_certs) {
        (Some(_), Some(_)) => {
            return Err(invalid(
                path,
                "trusted_ca and system_root_certs are mutually exclusive",
            ))
        }
        (Some(ds), None) => CaSource::TrustedCa(convert_data_source(
            Some(ds),
            &format!("{path}.trusted_ca"),
        )?),
        (None, Some(_)) => CaSource::SystemRoots,
        (None, None) => {
            return Err(invalid(
                path,
                "a CA source (trusted_ca or system_root_certs) is required",
            ))
        }
    };

    let mut san_matchers = Vec::with_capacity(vc.match_typed_subject_alt_names.len());
    for (i, m) in vc.match_typed_subject_alt_names.iter().enumerate() {
        san_matchers.push(convert_san_matcher(
            m,
            &format!("{path}.match_typed_subject_alt_names[{i}]"),
        )?);
    }

    Ok(ValidationContextIR {
        ca,
        san_matchers,
        allow_expired_certificate: vc.allow_expired_certificate,
    })
}

fn convert_san_matcher(
    m: &tls_v3::SubjectAltNameMatcher,
    path: &str,
) -> Result<SanMatcherIR, ConfigError> {
    use tls_v3::subject_alt_name_matcher::SanType as ProtoSanType;
    let san_type = match ProtoSanType::try_from(m.san_type) {
        Ok(ProtoSanType::Dns) => SanType::Dns,
        Ok(ProtoSanType::Uri) => SanType::Uri,
        Ok(ProtoSanType::IpAddress) => SanType::IpAddress,
        Ok(ProtoSanType::Email) | Ok(ProtoSanType::OtherName) | Ok(ProtoSanType::Unspecified) => {
            return Err(unsupported(
                format!("{path}.san_type"),
                "only DNS, URI, and IP_ADDRESS SAN types are implemented",
            ))
        }
        Err(_) => {
            return Err(invalid(
                format!("{path}.san_type"),
                "unknown san_type enum value",
            ))
        }
    };
    let matcher = m
        .matcher
        .as_ref()
        .ok_or_else(|| invalid(format!("{path}.matcher"), "matcher is required"))?;
    let matcher = convert_string_matcher(matcher, &format!("{path}.matcher"))?;
    Ok(SanMatcherIR { san_type, matcher })
}

/// `envoy.type.matcher.v3.StringMatcher` -> IR. `ignore_case` only makes
/// sense for exact/prefix/suffix/contains (the proto doc says as much);
/// combining it with `safe_regex` is meaningless, so — per AGENTS.md invariant 1 —
/// it's rejected rather than silently ignored.
fn convert_string_matcher(
    sm: &matcher_v3::StringMatcher,
    path: &str,
) -> Result<StringMatcherIR, ConfigError> {
    use matcher_v3::string_matcher::MatchPattern;
    let ignore_case = sm.ignore_case;
    match &sm.match_pattern {
        Some(MatchPattern::Exact(v)) => Ok(StringMatcherIR::Exact {
            value: v.clone(),
            ignore_case,
        }),
        Some(MatchPattern::Prefix(v)) => Ok(StringMatcherIR::Prefix {
            value: v.clone(),
            ignore_case,
        }),
        Some(MatchPattern::Suffix(v)) => Ok(StringMatcherIR::Suffix {
            value: v.clone(),
            ignore_case,
        }),
        Some(MatchPattern::Contains(v)) => Ok(StringMatcherIR::Contains {
            value: v.clone(),
            ignore_case,
        }),
        Some(MatchPattern::SafeRegex(re)) => {
            if ignore_case {
                return Err(invalid(
                    path,
                    "ignore_case cannot be combined with safe_regex",
                ));
            }
            Ok(StringMatcherIR::SafeRegex(compile_regex(
                &re.regex,
                &format!("{path}.safe_regex.regex"),
            )?))
        }
        Some(MatchPattern::Custom(_)) => Err(unsupported(
            format!("{path}.custom"),
            "custom string-matcher extensions are not implemented",
        )),
        None => Err(invalid(path, "a match pattern is required")),
    }
}

fn convert_data_source(
    ds: Option<&core_v3::DataSource>,
    path: &str,
) -> Result<DataSourceIR, ConfigError> {
    use core_v3::data_source::Specifier;
    let ds = ds.ok_or_else(|| invalid(path, "value is required"))?;
    match &ds.specifier {
        Some(Specifier::Filename(f)) => Ok(DataSourceIR::File(f.into())),
        Some(Specifier::InlineString(s)) => Ok(DataSourceIR::Inline(s.clone())),
        Some(_) => Err(unsupported(
            path,
            "only filename and inline_string data sources are implemented",
        )),
        None => Err(invalid(path, "a data source specifier is required")),
    }
}

/// Direct-response bodies are immutable request-independent data. Resolve
/// file sources while compiling the snapshot so request workers never touch
/// the filesystem.
fn convert_direct_response_body(
    ds: &core_v3::DataSource,
    path: &str,
) -> Result<DataSourceIR, ConfigError> {
    match convert_data_source(Some(ds), path)? {
        DataSourceIR::Inline(body) => Ok(DataSourceIR::Inline(body)),
        DataSourceIR::File(file) => std::fs::read_to_string(&file)
            .map(DataSourceIR::Inline)
            .map_err(|error| ConfigError::Io {
                path: file.display().to_string(),
                reason: error.to_string(),
            }),
    }
}

// ----------------------------------------------------------------- clusters --

/// `CustomClusterType.name` for the one custom cluster type implemented.
const AGGREGATE_CLUSTER_TYPE_NAME: &str = "envoy.clusters.aggregate";

/// `CustomClusterType.typed_config`'s expected type name for an aggregate
/// cluster.
const AGGREGATE_CLUSTER_CONFIG_TYPE: &str = "envoy.extensions.clusters.aggregate.v3.ClusterConfig";

fn convert_cluster(c: &cluster_v3::Cluster, path: &str) -> Result<ClusterConfig, ConfigError> {
    use cluster_v3::cluster::{
        ClusterDiscoveryType, DiscoveryType as ProtoDiscovery, LbPolicy as ProtoLb,
    };

    // `discovery` and `kind` come out of the same `cluster_discovery_type`
    // oneof match -- an aggregate cluster (`ClusterType`) has no discovery
    // mechanism of its own, so the two questions ("how do I turn this
    // cluster's own endpoints into hosts" vs "does this cluster own hosts at
    // all") have to be answered together here, even though `ClusterConfig`
    // keeps them as separate fields (see its `kind` doc for why).
    let dns_fields = dns_refresh_fields(c);
    let (discovery, kind) = match &c.cluster_discovery_type {
        None => (DiscoveryType::Static, ClusterKind::Endpoints), // proto default: STATIC
        Some(ClusterDiscoveryType::Type(t)) => match ProtoDiscovery::try_from(*t) {
            Ok(ProtoDiscovery::Static) => (DiscoveryType::Static, ClusterKind::Endpoints),
            Ok(ProtoDiscovery::StrictDns) => (
                DiscoveryType::StrictDns(convert_dns_refresh(&dns_fields, path)?),
                ClusterKind::Endpoints,
            ),
            Ok(ProtoDiscovery::LogicalDns) => (
                DiscoveryType::LogicalDns(convert_dns_refresh(&dns_fields, path)?),
                ClusterKind::Endpoints,
            ),
            Ok(ProtoDiscovery::Eds) => (DiscoveryType::Eds, ClusterKind::Endpoints),
            _ => {
                return Err(unsupported(
                    format!("{path}.type"),
                    "this discovery type is not implemented",
                ))
            }
        },
        Some(ClusterDiscoveryType::ClusterType(ct)) => {
            if ct.name != AGGREGATE_CLUSTER_TYPE_NAME {
                return Err(unsupported(
                    format!("{path}.cluster_type.name"),
                    format!(
                        "only `{AGGREGATE_CLUSTER_TYPE_NAME}` custom cluster types are \
                         implemented, found `{}`",
                        ct.name
                    ),
                ));
            }
            let cfg_path = format!("{path}.cluster_type.typed_config");
            let any = ct
                .typed_config
                .as_ref()
                .ok_or_else(|| invalid(&cfg_path, "typed_config is required"))?;
            if type_name(any) != AGGREGATE_CLUSTER_CONFIG_TYPE {
                return Err(ConfigError::UnknownTypeUrl {
                    field_path: cfg_path,
                    type_url: any.type_url.clone(),
                });
            }
            let agg: aggregate_cluster_v3::ClusterConfig = decode_any(any, &cfg_path)?;
            // Belt and suspenders: the proto's own `repeated.min_items = 1`
            // PGV annotation on `clusters` already rejects this during
            // `parse_bootstrap` (`validate::validate_message`), before
            // `convert_cluster` ever runs, so this arm is unreachable through
            // the normal `parse_bootstrap` -> `build_snapshot` pipeline today.
            // It stays because `build_snapshot`'s own doc only promises it is
            // "the only door between protobuf-land and the data plane" --
            // nothing guarantees every future caller of it validated first
            // (module doc: xDS resources will run PGV too, but haven't yet).
            if agg.clusters.is_empty() {
                return Err(invalid(
                    format!("{cfg_path}.clusters"),
                    "an aggregate cluster needs at least one member",
                ));
            }
            (
                // Inert: an aggregate is forbidden from carrying its own
                // endpoints (rejected below), so `convert_endpoint` never
                // runs for one and this value is never read.
                DiscoveryType::Static,
                ClusterKind::Aggregate {
                    // Member order IS the failover order (S7 / `ClusterKind`'s
                    // doc) -- preserve `clusters`' listed order exactly.
                    members: agg.clusters.clone(),
                },
            )
        }
    };
    let is_aggregate = matches!(kind, ClusterKind::Aggregate { .. });

    // Envoy ignores the DNS refresh settings on any cluster that does not
    // re-resolve on a timer. A config that sets one there almost always
    // changed the cluster's type and left the setting behind, so reject it
    // with its path instead of ignoring it (AGENTS.md invariant 1).
    if discovery.dns_refresh().is_none() {
        let cluster_type = if is_aggregate {
            "an aggregate cluster"
        } else if discovery == DiscoveryType::Eds {
            "an EDS cluster"
        } else {
            "a STATIC cluster"
        };
        reject_inert_dns_refresh(&dns_fields, path, cluster_type)?;
    }

    // `eds_cluster_config`'s shape and defaulting, only
    // consulted for the `Eds` arm just above -- see `convert_eds_cluster_config`.
    let eds = match discovery {
        DiscoveryType::Eds => Some(convert_eds_cluster_config(c, path)?),
        _ => None,
    };

    let lb_policy = match ProtoLb::try_from(c.lb_policy) {
        Ok(ProtoLb::RoundRobin) => LbPolicy::RoundRobin,
        Ok(ProtoLb::LeastRequest) => LbPolicy::LeastRequest,
        Ok(ProtoLb::Random) => LbPolicy::Random,
        Ok(ProtoLb::ClusterProvided) => LbPolicy::ClusterProvided,
        // RING_HASH / MAGLEV: the `LbPolicy` variants exist so the IR can
        // model them, but we deliberately do not implement them yet --
        // a consistent-hash that isn't bit-identical to Envoy's silently
        // breaks session affinity across a mixed fleet, so it needs an Envoy
        // differential harness first. Reject at *config* time rather than at
        // cluster-build time: `proxy-cluster` also refuses to build such a
        // cluster, but that error surfaces after startup, leaving the cluster
        // simply absent and every request to it answered 503 with no
        // explanation. Failing here means `make validate` and startup say
        // exactly what is wrong, with the full dotted path (AGENTS.md invariant 1).
        Ok(policy @ (ProtoLb::RingHash | ProtoLb::Maglev)) => {
            return Err(unsupported(
                format!("{path}.lb_policy"),
                format!(
                    "{} load balancing is not implemented yet (it requires \
                     bit-exact parity with Envoy's hashing, verified by a differential test, \
                     or session affinity breaks across a mixed fleet)",
                    policy.as_str_name()
                ),
            ))
        }
        _ => {
            return Err(unsupported(
                format!("{path}.lb_policy"),
                "this LB policy is not implemented",
            ))
        }
    };

    // Envoy requires `lb_policy: CLUSTER_PROVIDED` on an aggregate cluster
    // (it has no hosts of its own to run a real policy over) and forbids it
    // everywhere else (we implement no cluster-provided host-picking for a
    // cluster that owns hosts) -- see `LbPolicy::ClusterProvided`'s doc.
    if is_aggregate && lb_policy != LbPolicy::ClusterProvided {
        return Err(invalid(
            format!("{path}.lb_policy"),
            "an aggregate cluster (cluster_type: envoy.clusters.aggregate) requires \
             lb_policy: CLUSTER_PROVIDED; note the proto default when lb_policy is unset (0) \
             is ROUND_ROBIN, so it must be set explicitly",
        ));
    }
    if !is_aggregate && lb_policy == LbPolicy::ClusterProvided {
        return Err(unsupported(
            format!("{path}.lb_policy"),
            "CLUSTER_PROVIDED is only implemented for envoy.clusters.aggregate (cluster_type); \
             this cluster owns its own hosts and needs a real host-picking policy",
        ));
    }

    let connect_timeout = match &c.connect_timeout {
        Some(d) => to_std_duration(d, &format!("{path}.connect_timeout"))?,
        None => DEFAULT_CONNECT_TIMEOUT,
    };

    // Everything below is inert on an aggregate cluster: the member that
    // actually serves a request supplies its own endpoints, TLS, upstream
    // protocol, and (for the dialect) credentials -- AGENTS.md invariant 1 forbids
    // silently accepting-and-ignoring any of them, so each is a hard error
    // naming its own dotted path rather than a silent no-op.
    if is_aggregate {
        if c.load_assignment.is_some() {
            return Err(invalid(
                format!("{path}.load_assignment"),
                "an aggregate cluster has no endpoints of its own -- hosts come from its \
                 members",
            ));
        }
        if c.transport_socket.is_some() {
            return Err(invalid(
                format!("{path}.transport_socket"),
                "inert on an aggregate cluster: the member cluster that actually serves a \
                 request supplies its own TLS",
            ));
        }
        if !c.typed_extension_protocol_options.is_empty() {
            return Err(invalid(
                format!("{path}.typed_extension_protocol_options"),
                "inert on an aggregate cluster: the member cluster that actually serves a \
                 request supplies the upstream protocol",
            ));
        }
        if c.metadata.is_some() {
            return Err(invalid(
                format!("{path}.metadata"),
                "inert on an aggregate cluster, and dangerous if it carries \
                 `io.llmproxy.provider_auth` or `io.llmproxy.usage`: credentials or the usage \
                 dialect set here would silently never apply -- they belong on the member \
                 cluster that actually serves the request",
            ));
        }
    }

    // An EDS cluster's endpoints come from the EDS stream, not from its own
    // `load_assignment` -- unlike the aggregate case above, an *empty*
    // `load_assignment` (no locality carries any `lb_endpoints`) is harmless
    // and left alone, since it lowers to the same empty `endpoints` an EDS
    // cluster needs anyway. A non-empty one is rejected: its hosts would be
    // silently ignored in favour of the EDS-delivered set, AGENTS.md invariant 1's
    // exact shape.
    if discovery == DiscoveryType::Eds {
        let has_any_endpoint = c.load_assignment.as_ref().is_some_and(|la| {
            la.endpoints
                .iter()
                .any(|locality| !locality.lb_endpoints.is_empty())
        });
        if has_any_endpoint {
            return Err(invalid(
                format!("{path}.load_assignment"),
                "an EDS cluster's endpoints come from the EDS stream, not load_assignment -- \
                 they would be silently ignored in favour of the EDS-delivered set",
            ));
        }
    }

    let mut endpoints = Vec::new();
    if let Some(la) = &c.load_assignment {
        for (i, locality) in la.endpoints.iter().enumerate() {
            let priority = locality.priority;
            for (j, lbe) in locality.lb_endpoints.iter().enumerate() {
                let e_path = format!("{path}.load_assignment.endpoints[{i}].lb_endpoints[{j}]");
                endpoints.push(convert_endpoint(lbe, priority, discovery, &e_path)?);
            }
        }
    }

    let transport_socket = c
        .transport_socket
        .as_ref()
        .map(|ts| convert_upstream_tls(ts, &format!("{path}.transport_socket")))
        .transpose()?;

    // Circuit breakers stay meaningful on an aggregate: the router applies
    // the breaker to the *routed* cluster before the host pick, matching
    // Envoy, so an aggregate's own thresholds do real work even though it
    // has no hosts of its own.
    let circuit_breakers = convert_circuit_breakers(&c.circuit_breakers, path)?;
    let upstream_protocol = convert_upstream_protocol(&c.typed_extension_protocol_options, path)?;
    // Envoy-mode config has no proto field for per-provider auth headers --
    // see `ClusterConfig::request_headers_to_add`'s doc comment. The
    // `llmproxy` dialect lowers through this same Envoy-shaped pipeline
    // ("one engine, two front-ends"), so it smuggles the headers through
    // `Cluster.metadata.filter_metadata["io.llmproxy.provider_auth"]`
    // instead; a hand-written Envoy config that never sets this namespace
    // gets an empty list here, unchanged from before.
    let request_headers_to_add = convert_provider_auth_metadata(c.metadata.as_ref(), path)?;
    let provider_runtime = convert_provider_runtime_metadata(c.metadata.as_ref(), path)?;
    // A known instance of AGENTS.md invariant 6: the usage-filter dialect
    // is per-provider, so it rides the same `Cluster.metadata.filter_metadata`
    // smuggling channel as credentials above, under its own namespace.
    let usage_dialect = convert_usage_dialect_metadata(c.metadata.as_ref(), path)?;
    let request_path_rewrite = convert_request_path_rewrite_metadata(c.metadata.as_ref(), path)?;
    // S6 active health checking: meaningful on an aggregate too, in
    // principle, but Envoy runs health checks against a cluster's own hosts
    // -- an aggregate has none -- so `c.health_checks` on one is inert the
    // same way `load_assignment` is, and gets the same treatment below.
    if is_aggregate && !c.health_checks.is_empty() {
        return Err(invalid(
            format!("{path}.health_checks"),
            "inert on an aggregate cluster: it has no hosts of its own to probe -- health \
             checking belongs on the member cluster that actually serves the request",
        ));
    }
    let health_check = convert_health_check(&c.health_checks, path)?;
    // S6 passive outlier detection: same aggregate reasoning as
    // `health_checks` just above -- ejection acts on a cluster's own hosts,
    // and an aggregate has none, so an `outlier_detection` block on one is
    // inert and rejected rather than silently ignored.
    if is_aggregate && c.outlier_detection.is_some() {
        return Err(invalid(
            format!("{path}.outlier_detection"),
            "inert on an aggregate cluster: it has no hosts of its own to eject -- outlier \
             detection belongs on the member cluster that actually serves the request",
        ));
    }
    let outlier_detection = convert_outlier_detection(c.outlier_detection.as_ref(), path)?;

    Ok(ClusterConfig {
        name: c.name.clone(),
        discovery,
        lb_policy,
        connect_timeout,
        endpoints,
        kind,
        transport_socket,
        per_connection_buffer_limit_bytes: c
            .per_connection_buffer_limit_bytes
            .unwrap_or(DEFAULT_CONN_BUFFER_LIMIT),
        circuit_breakers,
        upstream_protocol,
        request_headers_to_add,
        request_path_rewrite,
        provider_runtime,
        usage_dialect,
        health_check,
        outlier_detection,
        eds,
    })
}

/// The four cluster-level DNS refresh settings, borrowed from a `Cluster`.
/// Exists so the deprecated proto fields are read in exactly one place
/// ([`dns_refresh_fields`]); everything else works on this struct.
struct DnsRefreshFields<'a> {
    dns_refresh_rate: Option<&'a prost_types::Duration>,
    dns_jitter: Option<&'a prost_types::Duration>,
    dns_failure_refresh_rate: Option<&'a cluster_v3::cluster::RefreshRate>,
    respect_dns_ttl: bool,
}

/// Read the DNS refresh settings off a `Cluster`.
///
/// Rust note: Envoy deprecated these fields in favor of configuring a
/// `DnsCluster` extension through `cluster_type`, and prost carries that over
/// as `#[deprecated]` on each generated field. The extension is not
/// implemented here, so the deprecated fields are the only way an Envoy
/// config can set DNS timing and reading them is the point; the lint is
/// silenced on this one function rather than the module.
#[allow(deprecated)]
fn dns_refresh_fields(c: &cluster_v3::Cluster) -> DnsRefreshFields<'_> {
    DnsRefreshFields {
        dns_refresh_rate: c.dns_refresh_rate.as_ref(),
        dns_jitter: c.dns_jitter.as_ref(),
        dns_failure_refresh_rate: c.dns_failure_refresh_rate.as_ref(),
        respect_dns_ttl: c.respect_dns_ttl,
    }
}

/// Envoy's shared lower bound for DNS intervals: its proto rule is
/// `duration.gt = 1ms`, so exactly 1ms is rejected.
const MIN_DNS_INTERVAL_EXCLUSIVE: StdDuration = StdDuration::from_millis(1);

/// One DNS interval: non-negative (like every duration here) and above
/// Envoy's 1ms floor. The bootstrap file path also runs the proto's own
/// validation rule before lowering, but an xDS-delivered cluster does not, so
/// the check lives here as well.
fn convert_dns_interval(d: &prost_types::Duration, path: &str) -> Result<StdDuration, ConfigError> {
    let interval = to_std_duration(d, path)?;
    if interval <= MIN_DNS_INTERVAL_EXCLUSIVE {
        return Err(invalid(path, "must be greater than 1ms"));
    }
    Ok(interval)
}

/// `dns_refresh_rate`, `dns_jitter` and `dns_failure_refresh_rate` of a
/// `STRICT_DNS` or `LOGICAL_DNS` cluster -> [`DnsRefresh`], with Envoy's
/// defaults filled in (Envoy v1.38 `Cluster` proto):
///
/// - `dns_refresh_rate` defaults to 5s and must exceed 1ms.
/// - `dns_jitter` defaults to none and must not be negative.
/// - Unset `dns_failure_refresh_rate`: failed lookups retry at the refresh
///   rate. Set: `base_interval` is required (above 1ms), `max_interval` is
///   optional (above 1ms, at least the base) and defaults to 10 times the
///   base.
///
/// `respect_dns_ttl: true` is rejected: the resolver is `getaddrinfo`, which
/// does not report record TTLs, so there is no TTL to schedule on. Accepting
/// the flag and refreshing on the fixed rate instead would silently change
/// what the operator asked for.
fn convert_dns_refresh(
    fields: &DnsRefreshFields<'_>,
    path: &str,
) -> Result<DnsRefresh, ConfigError> {
    if fields.respect_dns_ttl {
        return Err(unsupported(
            format!("{path}.respect_dns_ttl"),
            "respect_dns_ttl: true is not implemented: lookups go through the platform resolver \
             (getaddrinfo), which does not report record TTLs. Remove it to re-resolve every \
             dns_refresh_rate (default 5s)",
        ));
    }
    let refresh_rate = match fields.dns_refresh_rate {
        Some(d) => convert_dns_interval(d, &format!("{path}.dns_refresh_rate"))?,
        None => DnsRefresh::ENVOY_DEFAULT.refresh_rate,
    };
    let jitter = match fields.dns_jitter {
        Some(d) => to_std_duration(d, &format!("{path}.dns_jitter"))?,
        None => StdDuration::ZERO,
    };
    let (failure_base_interval, failure_max_interval) = match fields.dns_failure_refresh_rate {
        None => (refresh_rate, refresh_rate),
        Some(failure) => {
            let failure_path = format!("{path}.dns_failure_refresh_rate");
            let base_path = format!("{failure_path}.base_interval");
            let base = failure
                .base_interval
                .as_ref()
                .ok_or_else(|| invalid(&base_path, "base_interval is required"))?;
            let base = convert_dns_interval(base, &base_path)?;
            let max = match &failure.max_interval {
                Some(d) => {
                    let max_path = format!("{failure_path}.max_interval");
                    let max = convert_dns_interval(d, &max_path)?;
                    if max < base {
                        return Err(invalid(
                            max_path,
                            "max_interval must be greater than or equal to base_interval",
                        ));
                    }
                    max
                }
                None => base.saturating_mul(10),
            };
            (base, max)
        }
    };
    Ok(DnsRefresh {
        refresh_rate,
        jitter,
        failure_base_interval,
        failure_max_interval,
    })
}

/// Reject any DNS refresh setting on a cluster that never re-resolves on a
/// timer (`cluster_type` says which kind, for the message). Envoy ignores the
/// settings there; see the call site for why we do not.
fn reject_inert_dns_refresh(
    fields: &DnsRefreshFields<'_>,
    path: &str,
    cluster_type: &str,
) -> Result<(), ConfigError> {
    let set = [
        ("dns_refresh_rate", fields.dns_refresh_rate.is_some()),
        ("dns_jitter", fields.dns_jitter.is_some()),
        (
            "dns_failure_refresh_rate",
            fields.dns_failure_refresh_rate.is_some(),
        ),
        ("respect_dns_ttl", fields.respect_dns_ttl),
    ];
    match set.iter().find(|(_, is_set)| *is_set) {
        Some((field, _)) => Err(unsupported(
            format!("{path}.{field}"),
            format!(
                "only applies to STRICT_DNS and LOGICAL_DNS clusters; this is {cluster_type}, \
                 where Envoy ignores it. Remove it, or change the cluster type if a DNS \
                 cluster was meant"
            ),
        )),
        None => Ok(()),
    }
}

/// `Cluster.eds_cluster_config` -> IR, called only for the `Eds` arm of
/// `convert_cluster`'s discovery match. Envoy requires this block to be set
/// on an EDS cluster, requires its `eds_config` to be set, and this project
/// has exactly one transport that can deliver it: the ADS client -- a
/// `path_config_source`, `api_config_source`, or `self` source is a
/// different delivery mechanism we do not implement.
fn convert_eds_cluster_config(
    c: &cluster_v3::Cluster,
    path: &str,
) -> Result<EdsClusterConfig, ConfigError> {
    let cfg_path = format!("{path}.eds_cluster_config");
    let eds_cfg = c
        .eds_cluster_config
        .as_ref()
        .ok_or_else(|| invalid(&cfg_path, "eds_cluster_config is required when type is EDS"))?;

    let eds_config_path = format!("{cfg_path}.eds_config");
    // `check_ads_source` (defined above, for `dynamic_resources`'s per-type
    // ConfigSources) says exactly what we mean here too: ADS and filesystem
    // forms are implemented. It returns `Ok(None)` for an unset
    // source, which for a *required* field is itself the error -- the arm
    // below is what turns that into one, since `check_ads_source` alone has
    // no way to know whether its caller's field was optional.
    let source = check_ads_source(eds_cfg.eds_config.as_ref(), &eds_config_path)?;
    if source.is_none() {
        return Err(invalid(
            &eds_config_path,
            "eds_cluster_config.eds_config is required for an EDS cluster",
        ));
    }
    if source
        .as_ref()
        .is_some_and(|source| source.initial_fetch_timeout.is_some())
    {
        return Err(unsupported(
            format!("{eds_config_path}.initial_fetch_timeout"),
            "EDS initial_fetch_timeout is not implemented; use the bootstrap CDS timeout",
        ));
    }

    // Rust note: `String::is_empty` rather than checking for a sentinel --
    // proto3 has no concept of an unset scalar field, so "unset" and "empty
    // string" are the same wire value; Envoy's own default-to-cluster-name
    // behavior for `service_name` is defined the same way.
    let service_name = if eds_cfg.service_name.is_empty() {
        c.name.clone()
    } else {
        eds_cfg.service_name.clone()
    };
    Ok(EdsClusterConfig { service_name })
}

/// A cross-cluster post-pass over the assembled
/// cluster map, checking that every aggregate's members are wired correctly.
/// It cannot run inside `build_snapshot`'s per-cluster loop -- a member
/// cluster may be declared *after* the aggregate that names it, and
/// declaration order must not matter, so the whole map has to exist first.
///
/// For every `ClusterKind::Aggregate`, walks its `members` in listed order
/// and rejects the first of:
/// - the aggregate naming itself (checked before the nested-aggregate check
///   below, so the error says plainly "names itself" rather than the more
///   confusing "member `agg` is itself an aggregate")
/// - a member naming no cluster in the snapshot ("unknown cluster")
/// - a member whose own `kind` is `Aggregate` -- aggregates cannot nest;
///   `ClusterHandle::select_aggregate_member` (`proxy-cluster/src/manager.rs`)
///   deliberately refuses to recurse into one, so that member would be
///   silently skipped at runtime rather than failing outright
/// - a duplicate member name within one aggregate -- always a runtime no-op,
///   since `LoadBalancerContext::attempted_clusters` skips a cluster already
///   tried this request
///
/// AGENTS.md invariant 1's shape exactly: each of these degrades into a silent
/// runtime no-op (a 503 with no explanation, or a fallback that never
/// receives traffic) instead of a config-time error, unless caught here.
///
/// Rust note: `sr.clusters` (the original proto list) is re-walked with
/// `enumerate()` rather than iterating `snapshot.clusters` (a `HashMap`,
/// keyed by name) so the error path can report the aggregate's original
/// config index -- the name-keyed IR map has already forgotten it, and a
/// `HashMap`'s iteration order is unspecified besides.
fn validate_cluster_graph(
    sr: &proxy_api::envoy::config::bootstrap::v3::bootstrap::StaticResources,
    snapshot: &ConfigSnapshot,
) -> Result<(), ConfigError> {
    for (i, c) in sr.clusters.iter().enumerate() {
        let ir = snapshot
            .clusters
            .get(&c.name)
            .expect("build_snapshot just inserted every sr.clusters entry by this same name");
        let ClusterKind::Aggregate { members } = &ir.kind else {
            continue;
        };
        let path = format!("static_resources.clusters[{i}].cluster_type.typed_config.clusters");
        let mut seen = std::collections::HashSet::new();
        for (j, member) in members.iter().enumerate() {
            let member_path = format!("{path}[{j}]");
            if member == &c.name {
                return Err(invalid(
                    &member_path,
                    format!("aggregate cluster `{}` names itself as a member", c.name),
                ));
            }
            let Some(member_ir) = snapshot.clusters.get(member) else {
                return Err(invalid(&member_path, format!("unknown cluster `{member}`")));
            };
            if matches!(member_ir.kind, ClusterKind::Aggregate { .. }) {
                return Err(invalid(
                    &member_path,
                    format!(
                        "member `{member}` is itself an aggregate cluster; aggregates cannot \
                         nest -- select_aggregate_member refuses to recurse into one, so this \
                         member would be silently skipped at runtime"
                    ),
                ));
            }
            if !seen.insert(member.as_str()) {
                return Err(invalid(
                    &member_path,
                    format!(
                        "duplicate member `{member}` in aggregate cluster `{}`",
                        c.name
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// Namespace key the `llmproxy` dialect uses to carry provider credentials
/// through `Cluster.metadata.filter_metadata` -- see
/// `ClusterConfig::request_headers_to_add`'s doc comment for why credentials
/// have to live on the cluster rather than the route.
const PROVIDER_AUTH_METADATA_KEY: &str = "io.llmproxy.provider_auth";

/// Namespace key the `llmproxy` dialect uses to carry provider-owned
/// upstream path/query rewriting through `Cluster.metadata.filter_metadata`.
const PATH_REWRITE_METADATA_KEY: &str = "io.llmproxy.path_rewrite";

/// Namespace key for provider-specific model URL templates.
const PATH_TEMPLATE_METADATA_KEY: &str = "io.llmproxy.path_template";

/// Lower `Cluster.metadata.filter_metadata["io.llmproxy.provider_auth"]`
/// into `ClusterConfig::request_headers_to_add`. The expected shape is
/// `{ headers: [ { key: "...", value: "..." }, ... ] }`; every entry lowers
/// to [`HeaderAppendAction::OverwriteIfExistsOrAdd`], matching what the
/// dialect used to emit at the route level.
///
/// `google.protobuf.Struct` is opaque to the reflective surface walk (it is
/// a well-known type, so `check_supported_surface` stops recursing at its
/// boundary), so AGENTS.md invariant 1's "every field maps or errors" guarantee has
/// to be re-implemented by hand here for this one namespace: any shape that
/// isn't exactly the one above -- wrong types, missing `key`/`value`,
/// unrecognized sub-keys -- is a hard error with its full dotted path, never
/// a silent skip. Any *other* `filter_metadata` namespace is left alone; it
/// belongs to a different (possibly future) consumer.
fn convert_provider_auth_metadata(
    metadata: Option<&core_v3::Metadata>,
    path: &str,
) -> Result<Vec<HeaderMutation>, ConfigError> {
    let Some(auth) = metadata.and_then(|m| m.filter_metadata.get(PROVIDER_AUTH_METADATA_KEY))
    else {
        return Ok(Vec::new());
    };
    let auth_path = format!("{path}.metadata.filter_metadata[\"{PROVIDER_AUTH_METADATA_KEY}\"]");

    // Rust note: `Struct::fields` is a `HashMap`, so sort keys before
    // reporting one to keep the error deterministic across runs.
    let mut unknown: Vec<&String> = auth
        .fields
        .keys()
        .filter(|k| {
            !matches!(
                k.as_str(),
                "headers"
                    | "scheme"
                    | "access_token"
                    | "region"
                    | "access_key_id"
                    | "secret_access_key"
                    | "session_token"
                    | "models"
                    | "tenant_credential"
                    | "request_field_policy"
            )
        })
        .collect();
    unknown.sort();
    if let Some(key) = unknown.first() {
        return Err(unsupported(
            format!("{auth_path}.{key}"),
            format!(
                "`{PROVIDER_AUTH_METADATA_KEY}` contains an unsupported field; supported fields are `headers`, provider credential fields, `models`, `tenant_credential`, and `request_field_policy`"
            ),
        ));
    }

    let Some(headers_value) = auth.fields.get("headers") else {
        return Ok(Vec::new());
    };
    let headers_path = format!("{auth_path}.headers");
    let list = match &headers_value.kind {
        Some(prost_types::value::Kind::ListValue(l)) => &l.values,
        _ => return Err(invalid(&headers_path, "must be a list")),
    };

    let mut out = Vec::with_capacity(list.len());
    for (i, item) in list.iter().enumerate() {
        let item_path = format!("{headers_path}[{i}]");
        let Some(prost_types::value::Kind::StructValue(entry)) = &item.kind else {
            return Err(invalid(
                &item_path,
                "must be an object with `key` and `value` string fields",
            ));
        };
        let mut entry_unknown: Vec<&String> = entry
            .fields
            .keys()
            .filter(|k| !matches!(k.as_str(), "key" | "value"))
            .collect();
        entry_unknown.sort();
        if let Some(key) = entry_unknown.first() {
            return Err(unsupported(
                format!("{item_path}.{key}"),
                "only `key` and `value` are supported",
            ));
        }
        out.push(HeaderMutation {
            key: provider_auth_string_field(entry, "key", &item_path)?,
            value: provider_auth_string_field(entry, "value", &item_path)?,
            action: HeaderAppendAction::OverwriteIfExistsOrAdd,
        });
    }
    Ok(out)
}

fn provider_auth_string_field(
    s: &prost_types::Struct,
    name: &str,
    path: &str,
) -> Result<String, ConfigError> {
    match s.fields.get(name).and_then(|v| v.kind.as_ref()) {
        Some(prost_types::value::Kind::StringValue(v)) => Ok(v.clone()),
        Some(_) => Err(invalid(format!("{path}.{name}"), "must be a string")),
        None => Err(invalid(format!("{path}.{name}"), "is required")),
    }
}

/// Lower the llmproxy-only provider credential and URL-template metadata.
/// These values have no Envoy proto equivalent, so this parser is the strict
/// boundary that keeps them from disappearing inside `google.protobuf.Struct`.
fn convert_provider_runtime_metadata(
    metadata: Option<&core_v3::Metadata>,
    path: &str,
) -> Result<Option<ProviderRuntimeConfig>, ConfigError> {
    let credential = metadata
        .and_then(|m| m.filter_metadata.get(PROVIDER_AUTH_METADATA_KEY))
        .map(|auth| {
            let auth_path =
                format!("{path}.metadata.filter_metadata[\"{PROVIDER_AUTH_METADATA_KEY}\"]");
            let scheme = match auth.fields.get("scheme") {
                None => None,
                Some(value) => match value.kind.as_ref() {
                    Some(prost_types::value::Kind::StringValue(value)) => Some(value.as_str()),
                    Some(_) => {
                        return Err(invalid(format!("{auth_path}.scheme"), "must be a string"))
                    }
                    None => return Err(invalid(format!("{auth_path}.scheme"), "must be a string")),
                },
            };
            // ADR-0007 decision 1: a tenant slot is a header API-key shape, so
            // it cannot sit beside an OAuth2 or SigV4 credential. Checked before
            // the generic allow-list so the error names the actual conflict.
            if matches!(scheme, Some("vertex-oauth2") | Some("bedrock-sigv4"))
                && auth.fields.contains_key("tenant_credential")
            {
                return Err(unsupported(
                    format!("{auth_path}.tenant_credential"),
                    "a tenant credential cannot be combined with a vertex-oauth2 or bedrock-sigv4 credential; only header API-key clusters can carry one",
                ));
            }
            let allowed = match scheme {
                None => &[
                    "headers",
                    "models",
                    "tenant_credential",
                    "request_field_policy",
                ][..],
                Some("vertex-oauth2") => &[
                    "headers",
                    "scheme",
                    "access_token",
                    "models",
                    "request_field_policy",
                ][..],
                Some("bedrock-sigv4") => &[
                    "headers",
                    "scheme",
                    "region",
                    "access_key_id",
                    "secret_access_key",
                    "session_token",
                    "models",
                    "request_field_policy",
                ][..],
                Some(_) => &[][..],
            };
            let mut unexpected: Vec<&String> = auth
                .fields
                .keys()
                .filter(|key| !allowed.contains(&key.as_str()))
                .collect();
            unexpected.sort();
            if let Some(key) = unexpected.first() {
                return Err(unsupported(
                    format!("{auth_path}.{key}"),
                    "provider credential field does not belong to selected scheme",
                ));
            }
            match scheme {
                None => Ok(None),
                Some("vertex-oauth2") => Ok(Some(ProviderCredential::VertexOAuth2 {
                    access_token: provider_auth_string_field(auth, "access_token", &auth_path)?,
                })),
                Some("bedrock-sigv4") => Ok(Some(ProviderCredential::BedrockSigV4 {
                    region: provider_auth_string_field(auth, "region", &auth_path)?,
                    access_key_id: provider_auth_string_field(auth, "access_key_id", &auth_path)?,
                    secret_access_key: provider_auth_string_field(
                        auth,
                        "secret_access_key",
                        &auth_path,
                    )?,
                    session_token: match auth.fields.get("session_token") {
                        None => None,
                        Some(_) => Some(provider_auth_string_field(
                            auth,
                            "session_token",
                            &auth_path,
                        )?),
                    },
                })),
                Some(other) => Err(unsupported(
                    format!("{auth_path}.scheme"),
                    format!("unsupported provider credential scheme `{other}`"),
                )),
            }
        })
        .transpose()?
        .flatten();

    let path_template = metadata
        .and_then(|m| m.filter_metadata.get(PATH_TEMPLATE_METADATA_KEY))
        .map(|template| {
            let template_path =
                format!("{path}.metadata.filter_metadata[\"{PATH_TEMPLATE_METADATA_KEY}\"]");
            let allowed = |key: &str| {
                matches!(
                    key,
                    "scheme" | "project" | "location" | "publisher" | "models"
                )
            };
            let mut unknown: Vec<&String> =
                template.fields.keys().filter(|key| !allowed(key)).collect();
            unknown.sort();
            if let Some(key) = unknown.first() {
                return Err(unsupported(
                    format!("{template_path}.{key}"),
                    format!("`{PATH_TEMPLATE_METADATA_KEY}` contains an unsupported field"),
                ));
            }
            let scheme = provider_auth_string_field(template, "scheme", &template_path)?;
            let allowed = match scheme.as_str() {
                "vertex" => ["scheme", "project", "location", "publisher", "models"].as_slice(),
                "bedrock" => ["scheme", "models"].as_slice(),
                _ => ["scheme"].as_slice(),
            };
            let mut unexpected: Vec<&String> = template
                .fields
                .keys()
                .filter(|key| !allowed.contains(&key.as_str()))
                .collect();
            unexpected.sort();
            if let Some(key) = unexpected.first() {
                return Err(unsupported(
                    format!("{template_path}.{key}"),
                    "provider path field does not belong to selected scheme",
                ));
            }
            let models = provider_model_rewrites(template, &template_path)?;
            match scheme.as_str() {
                "vertex" => Ok(ProviderPathTemplate::Vertex {
                    project: provider_auth_string_field(template, "project", &template_path)?,
                    location: provider_auth_string_field(template, "location", &template_path)?,
                    publisher: provider_auth_string_field(template, "publisher", &template_path)?,
                    models,
                }),
                "bedrock" => Ok(ProviderPathTemplate::Bedrock { models }),
                _ => Err(unsupported(
                    format!("{template_path}.scheme"),
                    format!("unsupported provider path template `{scheme}`"),
                )),
            }
        })
        .transpose()?;

    let model_rewrites = metadata
        .and_then(|m| m.filter_metadata.get(PROVIDER_AUTH_METADATA_KEY))
        .map(|auth| {
            let auth_path =
                format!("{path}.metadata.filter_metadata[\"{PROVIDER_AUTH_METADATA_KEY}\"]");
            provider_model_rewrites(auth, &auth_path)
        })
        .transpose()?
        .unwrap_or_default();

    let tenant_credential =
        match metadata.and_then(|m| m.filter_metadata.get(PROVIDER_AUTH_METADATA_KEY)) {
            Some(auth) => {
                let auth_path =
                    format!("{path}.metadata.filter_metadata[\"{PROVIDER_AUTH_METADATA_KEY}\"]");
                convert_tenant_credential_slot(auth, &auth_path)?
            }
            None => None,
        };

    let request_field_policy =
        match metadata.and_then(|m| m.filter_metadata.get(PROVIDER_AUTH_METADATA_KEY)) {
            Some(auth) => {
                let auth_path =
                    format!("{path}.metadata.filter_metadata[\"{PROVIDER_AUTH_METADATA_KEY}\"]");
                convert_request_field_policy(auth, &auth_path)?
            }
            None => RequestFieldPolicy::default(),
        };

    if credential.is_none()
        && path_template.is_none()
        && model_rewrites.is_empty()
        && request_field_policy.is_empty()
        && tenant_credential.is_none()
    {
        Ok(None)
    } else {
        Ok(Some(ProviderRuntimeConfig {
            credential,
            path_template,
            model_rewrites,
            request_field_policy,
            tenant_credential,
        }))
    }
}

/// Lower the optional `request_field_policy` object under
/// `io.llmproxy.provider_auth`: `deny` and `strip` are lists of non-empty
/// top-level body key names. Unknown keys, wrong types, empty names, and a
/// name in both lists are load errors with their full dotted path.
fn convert_request_field_policy(
    auth: &prost_types::Struct,
    auth_path: &str,
) -> Result<RequestFieldPolicy, ConfigError> {
    let Some(value) = auth.fields.get("request_field_policy") else {
        return Ok(RequestFieldPolicy::default());
    };
    let policy_path = format!("{auth_path}.request_field_policy");
    let Some(prost_types::value::Kind::StructValue(policy)) = value.kind.as_ref() else {
        return Err(invalid(
            &policy_path,
            "must be an object with `deny` and/or `strip` lists",
        ));
    };
    let mut unknown: Vec<&String> = policy
        .fields
        .keys()
        .filter(|key| !matches!(key.as_str(), "deny" | "strip"))
        .collect();
    unknown.sort();
    if let Some(key) = unknown.first() {
        return Err(unsupported(
            format!("{policy_path}.{key}"),
            "only `deny` and `strip` are supported",
        ));
    }
    let names = |field: &str| -> Result<Vec<String>, ConfigError> {
        let Some(value) = policy.fields.get(field) else {
            return Ok(Vec::new());
        };
        let list_path = format!("{policy_path}.{field}");
        let Some(prost_types::value::Kind::ListValue(list)) = value.kind.as_ref() else {
            return Err(invalid(&list_path, "must be a list of strings"));
        };
        let mut out = Vec::with_capacity(list.values.len());
        for (i, item) in list.values.iter().enumerate() {
            let Some(prost_types::value::Kind::StringValue(name)) = item.kind.as_ref() else {
                return Err(invalid(format!("{list_path}[{i}]"), "must be a string"));
            };
            if name.is_empty() {
                return Err(invalid(
                    format!("{list_path}[{i}]"),
                    "field name must not be empty",
                ));
            }
            out.push(name.clone());
        }
        Ok(out)
    };
    let deny = names("deny")?;
    let strip = names("strip")?;
    // A name in both lists has no sensible meaning (refuse or remove?), so
    // make the operator choose.
    for (i, name) in strip.iter().enumerate() {
        if deny.contains(name) {
            return Err(invalid(
                format!("{policy_path}.strip[{i}]"),
                format!("`{name}` is also in `deny`; a field cannot be both denied and stripped"),
            ));
        }
    }
    Ok(RequestFieldPolicy { deny, strip })
}

/// Lower the optional `tenant_credential` object under
/// `io.llmproxy.provider_auth` into a [`TenantCredentialSlot`] (ADR-0007).
/// `provider` is required and non-empty. `header` is required and must be a
/// valid HTTP header name; it is stored lowercased, the same way the HTTP
/// stack compares header names, so the router can write it without a case
/// check. `prefix` is optional, defaults to empty, and must be a valid header
/// value fragment, which rejects CR and LF so a tenant value cannot inject a
/// header. `verify_path` is optional and is checked by
/// [`tenant_credential_verify_path_problem`].
/// Any other key is a hard error with its full dotted path.
fn convert_tenant_credential_slot(
    auth: &prost_types::Struct,
    auth_path: &str,
) -> Result<Option<TenantCredentialSlot>, ConfigError> {
    let Some(value) = auth.fields.get("tenant_credential") else {
        return Ok(None);
    };
    let slot_path = format!("{auth_path}.tenant_credential");
    let slot = match value.kind.as_ref() {
        Some(prost_types::value::Kind::StructValue(slot)) => slot,
        _ => {
            return Err(invalid(
                &slot_path,
                "must be an object with `provider` and `header` string fields",
            ))
        }
    };

    let mut unknown: Vec<&String> = slot
        .fields
        .keys()
        .filter(|key| {
            !matches!(
                key.as_str(),
                "provider" | "header" | "prefix" | "verify_path"
            )
        })
        .collect();
    unknown.sort();
    if let Some(key) = unknown.first() {
        return Err(unsupported(
            format!("{slot_path}.{key}"),
            "only `provider`, `header`, `prefix`, and `verify_path` are supported",
        ));
    }

    let provider = provider_auth_string_field(slot, "provider", &slot_path)?;
    if provider.is_empty() {
        return Err(invalid(
            format!("{slot_path}.provider"),
            "must not be empty",
        ));
    }

    let header = provider_auth_string_field(slot, "header", &slot_path)?;
    // Rust note: `HeaderName::from_bytes` accepts upper- and lowercase input
    // alike; we validate first and only then lowercase the stored copy.
    if http::HeaderName::from_bytes(header.as_bytes()).is_err() {
        return Err(invalid(
            format!("{slot_path}.header"),
            "must be a valid HTTP header name",
        ));
    }

    let value_prefix = match slot.fields.get("prefix") {
        None => String::new(),
        Some(_) => provider_auth_string_field(slot, "prefix", &slot_path)?,
    };
    if http::HeaderValue::from_str(&value_prefix).is_err() {
        return Err(invalid(
            format!("{slot_path}.prefix"),
            "must be a valid header value fragment (no CR, LF, or control characters)",
        ));
    }

    let verify_path = match slot.fields.get("verify_path") {
        None => None,
        Some(_) => {
            let path = provider_auth_string_field(slot, "verify_path", &slot_path)?;
            if let Some(reason) = tenant_credential_verify_path_problem(&path) {
                return Err(invalid(format!("{slot_path}.verify_path"), reason));
            }
            Some(path)
        }
    };

    Ok(Some(TenantCredentialSlot {
        provider,
        header: header.to_ascii_lowercase(),
        value_prefix,
        verify_path,
    }))
}

/// Longest tenant `verify_path` accepted. Real probe paths are a few dozen
/// bytes; the cap keeps a config from putting an unbounded value in a request
/// line.
const MAX_VERIFY_PATH_BYTES: usize = 2048;

/// Why a tenant `verify_path` is refused, or `None` when it is acceptable
/// (ADR-0007 decision 10). The path is sent as the request target of a `GET`,
/// so it must be an origin-form path with nothing that could split the request
/// line. This is the one rule set for both dialects: `proxy-simple-config`
/// calls it and reports the reason at its own field path.
pub fn tenant_credential_verify_path_problem(path: &str) -> Option<String> {
    if path.len() > MAX_VERIFY_PATH_BYTES {
        return Some(format!("must be at most {MAX_VERIFY_PATH_BYTES} bytes"));
    }
    if !path.starts_with('/') {
        return Some("must start with `/`".to_string());
    }
    // Rust note: `is_ascii_graphic` is true exactly for bytes 0x21..=0x7E, so
    // one scan rejects whitespace, CR and LF, other controls, and non-ASCII.
    if !path.bytes().all(|b| b.is_ascii_graphic()) {
        return Some(
            "must not contain whitespace, control characters, or non-ASCII bytes".to_string(),
        );
    }
    // A fragment is never sent in a request target, so `#` is refused even
    // though `PathAndQuery` would parse it.
    if path.contains('#') {
        return Some(
            "must not contain `#`; a fragment is not part of a request target".to_string(),
        );
    }
    // Rust note: `TryFrom<&str>` for `PathAndQuery` does the full URI grammar
    // check (path characters, and an optional `?query`), so we reuse the
    // `http` crate's parser rather than hand-writing one.
    if http::uri::PathAndQuery::try_from(path).is_err() {
        return Some("must be a valid URI path with an optional query".to_string());
    }
    None
}

fn provider_model_rewrites(
    template: &prost_types::Struct,
    path: &str,
) -> Result<Vec<ProviderModelRewrite>, ConfigError> {
    let Some(value) = template.fields.get("models") else {
        return Ok(Vec::new());
    };
    let Some(prost_types::value::Kind::ListValue(list)) = value.kind.as_ref() else {
        return Err(invalid(format!("{path}.models"), "must be a list"));
    };
    let mut out = Vec::with_capacity(list.values.len());
    for (i, value) in list.values.iter().enumerate() {
        let item_path = format!("{path}.models[{i}]");
        let Some(prost_types::value::Kind::StructValue(item)) = value.kind.as_ref() else {
            return Err(invalid(&item_path, "must be an object"));
        };
        let mut unknown: Vec<&String> = item
            .fields
            .keys()
            .filter(|key| !matches!(key.as_str(), "pattern" | "upstream_model"))
            .collect();
        unknown.sort();
        if let Some(key) = unknown.first() {
            return Err(unsupported(
                format!("{item_path}.{key}"),
                "only `pattern` and `upstream_model` are supported",
            ));
        }
        out.push(ProviderModelRewrite {
            pattern: provider_auth_string_field(item, "pattern", &item_path)?,
            upstream_model: provider_auth_string_field(item, "upstream_model", &item_path)?,
        });
    }
    Ok(out)
}

/// Lower `Cluster.metadata.filter_metadata["io.llmproxy.path_rewrite"]` into
/// provider-owned request path IR. The namespace accepts exactly
/// `match_prefix`, `replacement_prefix`, and optional `query` string fields.
fn convert_request_path_rewrite_metadata(
    metadata: Option<&core_v3::Metadata>,
    path: &str,
) -> Result<Option<RequestPathRewrite>, ConfigError> {
    let Some(rewrite) = metadata.and_then(|m| m.filter_metadata.get(PATH_REWRITE_METADATA_KEY))
    else {
        return Ok(None);
    };
    let rewrite_path = format!("{path}.metadata.filter_metadata[\"{PATH_REWRITE_METADATA_KEY}\"]");
    let fields = rewrite;
    let mut unknown: Vec<&String> = fields
        .fields
        .keys()
        .filter(|key| {
            !matches!(
                key.as_str(),
                "match_prefix" | "replacement_prefix" | "query"
            )
        })
        .collect();
    unknown.sort();
    if let Some(key) = unknown.first() {
        return Err(unsupported(
            format!("{rewrite_path}.{key}"),
            format!(
                "`{PATH_REWRITE_METADATA_KEY}` only supports `match_prefix`, \
                 `replacement_prefix`, and `query`"
            ),
        ));
    }

    let string_field = |name: &str| -> Result<String, ConfigError> {
        let field_path = format!("{rewrite_path}.{name}");
        match fields
            .fields
            .get(name)
            .and_then(|value| value.kind.as_ref())
        {
            Some(prost_types::value::Kind::StringValue(value)) if !value.is_empty() => {
                Ok(value.clone())
            }
            Some(prost_types::value::Kind::StringValue(_)) => {
                Err(invalid(field_path, "must not be empty"))
            }
            Some(_) => Err(invalid(field_path, "must be a string")),
            None => Err(invalid(field_path, "is required")),
        }
    };
    let query = match fields.fields.get("query") {
        None => None,
        Some(value) => match value.kind.as_ref() {
            Some(prost_types::value::Kind::StringValue(query)) if !query.is_empty() => {
                Some(query.clone())
            }
            Some(prost_types::value::Kind::StringValue(_)) => {
                return Err(invalid(
                    format!("{rewrite_path}.query"),
                    "must not be empty",
                ))
            }
            Some(_) => return Err(invalid(format!("{rewrite_path}.query"), "must be a string")),
            None => return Err(invalid(format!("{rewrite_path}.query"), "must be a string")),
        },
    };
    Ok(Some(RequestPathRewrite {
        match_prefix: string_field("match_prefix")?,
        replacement_prefix: string_field("replacement_prefix")?,
        query,
    }))
}

/// Namespace key the `llmproxy` dialect uses to carry the usage-filter
/// dialect through `Cluster.metadata.filter_metadata` -- a known instance of
/// AGENTS.md invariant 6: the dialect is a per-provider property, so it
/// has to follow the cluster that is actually dialled, the same way
/// [`PROVIDER_AUTH_METADATA_KEY`] carries credentials. This key only
/// populates [`ClusterConfig::usage_dialect`]; the usage filter itself still
/// reads the route-level `typed_per_filter_config` copy until the cluster
/// value is plumbed through to it.
const USAGE_DIALECT_METADATA_KEY: &str = "io.llmproxy.usage";

/// Namespace for the route-level strict streaming assertion.  Route metadata
/// is an Envoy-native extensibility carrier, so the simple dialect can express
/// this without inventing a field that the strict Envoy parser would discard.
const STREAMING_METADATA_KEY: &str = "io.llmproxy.streaming";

/// Read `Route.metadata.filter_metadata["io.llmproxy.streaming"]`.
///
/// The only accepted form is `{ strict: true }`.  `false` is rejected instead
/// of silently acting like an absent assertion: the simple dialect exposes an
/// enum (`streaming: strict`), not a boolean whose false value has ambiguous
/// compatibility semantics.
fn convert_streaming_strict_metadata(
    metadata: Option<&core_v3::Metadata>,
    path: &str,
) -> Result<bool, ConfigError> {
    let Some(streaming) = metadata.and_then(|m| m.filter_metadata.get(STREAMING_METADATA_KEY))
    else {
        return Ok(false);
    };
    let streaming_path = format!("{path}.metadata.filter_metadata[\"{STREAMING_METADATA_KEY}\"]");
    let mut unknown: Vec<&String> = streaming
        .fields
        .keys()
        .filter(|k| k.as_str() != "strict")
        .collect();
    unknown.sort();
    if let Some(key) = unknown.first() {
        return Err(unsupported(
            format!("{streaming_path}.{key}"),
            format!("`{STREAMING_METADATA_KEY}` only supports `strict: true`"),
        ));
    }
    match streaming.fields.get("strict").and_then(|v| v.kind.as_ref()) {
        Some(prost_types::value::Kind::BoolValue(true)) => Ok(true),
        Some(prost_types::value::Kind::BoolValue(false)) => Err(invalid(
            format!("{streaming_path}.strict"),
            "must be true; omit `io.llmproxy.streaming` when strict streaming is not required",
        )),
        Some(_) => Err(invalid(
            format!("{streaming_path}.strict"),
            "must be a boolean",
        )),
        None => Err(invalid(format!("{streaming_path}.strict"), "is required")),
    }
}

/// Lower `Cluster.metadata.filter_metadata["io.llmproxy.usage"]` into
/// [`ClusterConfig::usage_dialect`]. The expected shape is
/// `{ dialect: "openai" | "anthropic" }`.
///
/// Same re-implementation-by-hand rationale as
/// [`convert_provider_auth_metadata`]: `google.protobuf.Struct` is opaque to
/// the reflective surface walk, so AGENTS.md invariant 1 has to be enforced here
/// directly -- an unrecognized `dialect` value, a missing `dialect` key, or
/// any unexpected key in the namespace is a hard error with its full dotted
/// path, never a silent skip. Any *other* `filter_metadata` namespace
/// (including [`PROVIDER_AUTH_METADATA_KEY`]) is left alone.
fn convert_usage_dialect_metadata(
    metadata: Option<&core_v3::Metadata>,
    path: &str,
) -> Result<Option<UsageDialect>, ConfigError> {
    let Some(usage) = metadata.and_then(|m| m.filter_metadata.get(USAGE_DIALECT_METADATA_KEY))
    else {
        return Ok(None);
    };
    let usage_path = format!("{path}.metadata.filter_metadata[\"{USAGE_DIALECT_METADATA_KEY}\"]");

    // Rust note: `Struct::fields` is a `HashMap`, so sort keys before
    // reporting one to keep the error deterministic across runs.
    let mut unknown: Vec<&String> = usage
        .fields
        .keys()
        .filter(|k| k.as_str() != "dialect")
        .collect();
    unknown.sort();
    if let Some(key) = unknown.first() {
        return Err(unsupported(
            format!("{usage_path}.{key}"),
            format!("`{USAGE_DIALECT_METADATA_KEY}` only supports a `dialect` string"),
        ));
    }

    let dialect_path = format!("{usage_path}.dialect");
    let dialect = match usage.fields.get("dialect").and_then(|v| v.kind.as_ref()) {
        Some(prost_types::value::Kind::StringValue(v)) => v.as_str(),
        Some(_) => return Err(invalid(&dialect_path, "must be a string")),
        None => return Err(invalid(&dialect_path, "is required")),
    };
    match dialect {
        "openai" => Ok(Some(UsageDialect::OpenAi)),
        "anthropic" => Ok(Some(UsageDialect::Anthropic)),
        other => Err(invalid(
            &dialect_path,
            format!("unrecognized dialect `{other}`; expected `openai` or `anthropic`"),
        )),
    }
}

// ------------------------------------------------------------------ tracing --

/// Namespace key the `llmproxy` dialect uses to carry [`TracingConfig`]
/// through `Bootstrap.node.metadata` -- see [`convert_tracing_metadata`]'s
/// doc for why this carrier (rather than the real `HttpConnectionManager.
/// tracing.provider` field, which Envoy mode rejects outright -- see
/// `convert_hcm`) is what actually produces the IR value today.
const TRACING_METADATA_KEY: &str = "io.llmproxy.tracing";

/// Lower `Bootstrap.node.metadata["io.llmproxy.tracing"]` into
/// [`ConfigSnapshot::tracing`]. The expected shape is
/// `{ otlp_endpoint: "..." (required), service_name: "..." (optional,
/// default "llm-proxy"), sample_ratio: 0.0..=1.0 (optional, default 1.0) }`.
///
/// `Node.metadata` (unlike `Cluster.metadata`) is a bare
/// `google.protobuf.Struct`, not wrapped in a `filter_metadata` map -- so
/// this reads the namespace key directly out of it rather than through a
/// `filter_metadata` lookup, but is otherwise the same
/// re-implementation-by-hand pattern as
/// `convert_provider_auth_metadata`/`convert_usage_dialect_metadata`:
/// `google.protobuf.Struct` is opaque to the reflective surface walk, so
/// AGENTS.md invariant 1 has to be enforced here directly, and any error names its
/// full dotted path rather than a silent skip. A real Envoy config's
/// `node.metadata` may carry anything else under any other key; only this
/// one namespace is ever inspected, and nothing else there is touched.
fn convert_tracing_metadata(
    node: Option<&core_v3::Node>,
    path: &str,
) -> Result<Option<TracingConfig>, ConfigError> {
    let Some(tracing) = node
        .and_then(|n| n.metadata.as_ref())
        .and_then(|m| m.fields.get(TRACING_METADATA_KEY))
    else {
        return Ok(None);
    };
    let tracing_path = format!("{path}.metadata[\"{TRACING_METADATA_KEY}\"]");
    let Some(prost_types::value::Kind::StructValue(tracing)) = &tracing.kind else {
        return Err(invalid(&tracing_path, "must be an object"));
    };

    // Rust note: `Struct::fields` is a `HashMap`, so sort keys before
    // reporting one to keep the error deterministic across runs.
    let mut unknown: Vec<&String> = tracing
        .fields
        .keys()
        .filter(|k| {
            !matches!(
                k.as_str(),
                "otlp_endpoint" | "service_name" | "sample_ratio" | "export_deadline"
            )
        })
        .collect();
    unknown.sort();
    if let Some(key) = unknown.first() {
        return Err(unsupported(
            format!("{tracing_path}.{key}"),
            format!(
                "`{TRACING_METADATA_KEY}` only supports `otlp_endpoint`, `service_name`, \
                 `sample_ratio`, and `export_deadline`"
            ),
        ));
    }

    let endpoint_path = format!("{tracing_path}.otlp_endpoint");
    let otlp_endpoint = match tracing
        .fields
        .get("otlp_endpoint")
        .and_then(|v| v.kind.as_ref())
    {
        Some(prost_types::value::Kind::StringValue(v)) if !v.is_empty() => v.clone(),
        Some(prost_types::value::Kind::StringValue(_)) => {
            return Err(invalid(&endpoint_path, "must not be empty"))
        }
        Some(_) => return Err(invalid(&endpoint_path, "must be a string")),
        None => return Err(invalid(&endpoint_path, "is required")),
    };

    let service_name_path = format!("{tracing_path}.service_name");
    let service_name = match tracing
        .fields
        .get("service_name")
        .and_then(|v| v.kind.as_ref())
    {
        Some(prost_types::value::Kind::StringValue(v)) => v.clone(),
        Some(_) => return Err(invalid(&service_name_path, "must be a string")),
        None => "llm-proxy".to_string(),
    };

    let ratio_path = format!("{tracing_path}.sample_ratio");
    let sample_ratio = match tracing
        .fields
        .get("sample_ratio")
        .and_then(|v| v.kind.as_ref())
    {
        Some(prost_types::value::Kind::NumberValue(v)) => *v,
        Some(_) => return Err(invalid(&ratio_path, "must be a number")),
        None => 1.0,
    };
    if !(0.0..=1.0).contains(&sample_ratio) {
        return Err(invalid(&ratio_path, "must be between 0.0 and 1.0"));
    }

    // Same shape as `export_deadline` in `convert_metrics_metadata` below:
    // seconds numbers, bounded away from the two degenerate extremes. There
    // is no cross-field check here because the trace batch interval is a
    // fixed constant, not a config field -- unlike the metric side, which
    // validates the deadline against the interval it is paired with. The
    // ceiling (`TRACE_EXPORT_DEADLINE_MAX`) is imported from the module that
    // actually enforces deadline semantics, so the loader cannot drift from
    // the exporter's own bound on what a sane deadline is.
    let deadline_path = format!("{tracing_path}.export_deadline");
    let export_deadline = match tracing
        .fields
        .get("export_deadline")
        .and_then(|v| v.kind.as_ref())
    {
        Some(prost_types::value::Kind::NumberValue(v)) => seconds_to_duration(*v, &deadline_path)?,
        Some(_) => return Err(invalid(&deadline_path, "must be a number of seconds")),
        None => DEFAULT_TRACING_EXPORT_DEADLINE,
    };
    if export_deadline < METRICS_EXPORT_DEADLINE_MIN {
        return Err(invalid(
            &deadline_path,
            format!(
                "must be at least {}ms, got {}s",
                METRICS_EXPORT_DEADLINE_MIN.as_millis(),
                export_deadline.as_secs_f64()
            ),
        ));
    }
    if export_deadline > TRACE_EXPORT_DEADLINE_MAX {
        return Err(invalid(
            &deadline_path,
            format!(
                "must be at most {}s, got {}s",
                TRACE_EXPORT_DEADLINE_MAX.as_secs(),
                export_deadline.as_secs_f64()
            ),
        ));
    }

    Ok(Some(TracingConfig {
        otlp_endpoint,
        service_name,
        sample_ratio,
        export_deadline,
    }))
}

// ----------------------------------------------------------------- metrics --

/// Namespace key the `llmproxy` dialect uses to carry [`MetricsExportConfig`]
/// through `Bootstrap.node.metadata` -- the same carrier, and for the same
/// reason, as [`TRACING_METADATA_KEY`]; see [`convert_tracing_metadata`]'s doc
/// for why `Node.metadata` stands in for the real-but-unmapped
/// `HttpConnectionManager.tracing.provider`.
///
/// A different key from the tracing one, and that is the load-bearing detail:
/// `io.llmproxy.metrics` is readable and writable with no
/// `io.llmproxy.tracing` present, which is what makes "export metrics, turn
/// traces off" expressible at all.
const METRICS_METADATA_KEY: &str = "io.llmproxy.metrics";

/// Bounds on [`MetricsExportConfig::export_interval`]. The floor keeps a
/// typo'd `0.1` from turning the exporter into a busy loop that exports a
/// full cumulative snapshot ten times a second; the ceiling keeps a typo'd
/// `86400` (a plausible "once a day" slip for someone thinking in seconds when
/// the value is read as... seconds) from silently disabling metric export
/// entirely for a day at a time. Both are `Duration`-typed here so the same
/// parsed value flows into the IR without a second unit decision.
const METRICS_EXPORT_INTERVAL_MIN: StdDuration = StdDuration::from_secs(1);
const METRICS_EXPORT_INTERVAL_MAX: StdDuration = StdDuration::from_secs(3_600);
const METRICS_EXPORT_DEADLINE_MIN: StdDuration = StdDuration::from_millis(100);

/// Default export interval when the namespace omits `export_interval`. 15s is
/// the conventional OTel/Prometheus scrape default and is what a collector's
/// own dashboards are sized for; it is a default rather than a hardcoded
/// constant in the exporter because an operator whose collector charges per
/// request or runs a tight budget needs to be able to move it.
const DEFAULT_METRICS_EXPORT_INTERVAL: StdDuration = StdDuration::from_secs(15);

/// Default per-export deadline when the namespace omits `export_deadline`.
/// Comfortably under [`DEFAULT_METRICS_EXPORT_INTERVAL`] so the default pairing
/// satisfies the deadline-below-interval rule without the operator having to
/// think about it.
const DEFAULT_METRICS_EXPORT_DEADLINE: StdDuration = StdDuration::from_secs(10);

/// Default trace-batch export deadline for `io.llmproxy.tracing`. Matches the
/// fixed 5s batch interval, so the common case never times out against a
/// healthy collector while a wedged one costs one interval per attempt.
const DEFAULT_TRACING_EXPORT_DEADLINE: StdDuration = StdDuration::from_secs(5);

/// Lower `Bootstrap.node.metadata["io.llmproxy.metrics"]` into
/// [`ConfigSnapshot::metrics`]. The expected shape is
/// `{ otlp_endpoint: "..." (required), service_name: "..." (optional, default
/// "llm-proxy"), export_interval: <seconds> (optional, default 15),
/// export_deadline: <seconds> (optional, default 10) }`.
///
/// Structurally a sibling of [`convert_tracing_metadata`] -- same opaque
/// `google.protobuf.Struct` walk, same AGENTS.md invariant 1 enforcement, same
/// deterministic (sorted) unknown-key reporting -- with two additions the
/// tracing block has no reason to make:
///
/// - Durations arrive as plain `NumberValue` **seconds**, because a
///   `Struct` cannot express a protobuf `Duration` and the alternative
///   (a string like `"15s"`) would be a second mini-parser to keep
///   consistent with the `llmproxy` dialect's own duration syntax in
///   `proxy-simple-config` for no benefit at this surface.
/// - `export_deadline` is checked against `export_interval`, not just against
///   its own floor. A deadline at or above the interval is a configuration
///   that cannot do what it looks like it does: every tick's export would be
///   abandoned as a timeout before the next tick was even due, and
///   `MissedTickBehavior::Delay` would then hold each subsequent tick until
///   the previous one finished. Rejecting it at load is the only place this
///   can be caught, since the runtime has no way to act on it either way.
fn convert_metrics_metadata(
    node: Option<&core_v3::Node>,
    path: &str,
) -> Result<Option<MetricsExportConfig>, ConfigError> {
    let Some(metrics) = node
        .and_then(|n| n.metadata.as_ref())
        .and_then(|m| m.fields.get(METRICS_METADATA_KEY))
    else {
        return Ok(None);
    };
    let metrics_path = format!("{path}.metadata[\"{METRICS_METADATA_KEY}\"]");
    let Some(prost_types::value::Kind::StructValue(metrics)) = &metrics.kind else {
        return Err(invalid(&metrics_path, "must be an object"));
    };

    // Rust note: `Struct::fields` is a `HashMap`, so sort keys before
    // reporting one to keep the error deterministic across runs.
    let mut unknown: Vec<&String> = metrics
        .fields
        .keys()
        .filter(|k| {
            !matches!(
                k.as_str(),
                "otlp_endpoint" | "service_name" | "export_interval" | "export_deadline"
            )
        })
        .collect();
    unknown.sort();
    if let Some(key) = unknown.first() {
        return Err(unsupported(
            format!("{metrics_path}.{key}"),
            format!(
                "`{METRICS_METADATA_KEY}` only supports `otlp_endpoint`, `service_name`, \
                 `export_interval`, and `export_deadline`"
            ),
        ));
    }

    let endpoint_path = format!("{metrics_path}.otlp_endpoint");
    let otlp_endpoint = match metrics
        .fields
        .get("otlp_endpoint")
        .and_then(|v| v.kind.as_ref())
    {
        Some(prost_types::value::Kind::StringValue(v)) if !v.is_empty() => v.clone(),
        Some(prost_types::value::Kind::StringValue(_)) => {
            return Err(invalid(&endpoint_path, "must not be empty"))
        }
        Some(_) => return Err(invalid(&endpoint_path, "must be a string")),
        None => return Err(invalid(&endpoint_path, "is required")),
    };

    let service_name_path = format!("{metrics_path}.service_name");
    let service_name = match metrics
        .fields
        .get("service_name")
        .and_then(|v| v.kind.as_ref())
    {
        Some(prost_types::value::Kind::StringValue(v)) => v.clone(),
        Some(_) => return Err(invalid(&service_name_path, "must be a string")),
        None => "llm-proxy".to_string(),
    };

    let interval_path = format!("{metrics_path}.export_interval");
    let export_interval: StdDuration = match metrics
        .fields
        .get("export_interval")
        .and_then(|v| v.kind.as_ref())
    {
        Some(prost_types::value::Kind::NumberValue(v)) => seconds_to_duration(*v, &interval_path)?,
        Some(_) => return Err(invalid(&interval_path, "must be a number of seconds")),
        None => DEFAULT_METRICS_EXPORT_INTERVAL,
    };
    if !(METRICS_EXPORT_INTERVAL_MIN..=METRICS_EXPORT_INTERVAL_MAX).contains(&export_interval) {
        return Err(invalid(
            &interval_path,
            format!(
                "must be between {}s and {}s, got {}s",
                METRICS_EXPORT_INTERVAL_MIN.as_secs(),
                METRICS_EXPORT_INTERVAL_MAX.as_secs(),
                export_interval.as_secs_f64()
            ),
        ));
    }

    let deadline_path = format!("{metrics_path}.export_deadline");
    let export_deadline: StdDuration = match metrics
        .fields
        .get("export_deadline")
        .and_then(|v| v.kind.as_ref())
    {
        Some(prost_types::value::Kind::NumberValue(v)) => seconds_to_duration(*v, &deadline_path)?,
        Some(_) => return Err(invalid(&deadline_path, "must be a number of seconds")),
        None => DEFAULT_METRICS_EXPORT_DEADLINE,
    };
    if export_deadline < METRICS_EXPORT_DEADLINE_MIN {
        return Err(invalid(
            &deadline_path,
            format!(
                "must be at least {}ms, got {}s",
                METRICS_EXPORT_DEADLINE_MIN.as_millis(),
                export_deadline.as_secs_f64()
            ),
        ));
    }
    // The cross-field check, stated as its own error rather than folded into
    // either field's own range check so the message can name the relationship
    // rather than making the operator derive it: a deadline >= interval means
    // no export can ever complete before the next one is due.
    if export_deadline >= export_interval {
        return Err(invalid(
            &deadline_path,
            format!(
                "must be less than `export_interval` ({}s), got {}s -- otherwise every export \
                 is abandoned as a timeout before the next one is due",
                export_interval.as_secs_f64(),
                export_deadline.as_secs_f64()
            ),
        ));
    }

    Ok(Some(MetricsExportConfig {
        otlp_endpoint,
        service_name,
        export_interval,
        export_deadline,
    }))
}

/// Convert a `google.protobuf.Value` number of seconds into a [`StdDuration`],
/// rejecting every shape a `Struct` number can take that is not a usable
/// interval.
///
/// Rust note: the conversion is `Duration::try_from_secs_f64`, NOT
/// `from_secs_f64`. The panicking variant is guarded only against negative,
/// NaN, and infinite input -- a huge but perfectly finite value like `1e100`
/// sails past all three of those checks and still panics on overflow, and a
/// review found exactly that (`export_interval: 1.0e100` aborted config load
/// with exit code 101). `try_from_secs_f64` folds the overflow case into
/// `Err(Overflow)`, which this function turns into the same dotted-path
/// `ConfigError` as every other bad value -- the whole point being that no
/// number a config file can contain should be able to abort the process at
/// load time. `f64` also has far more exponent range than `Duration`'s
/// `u64`-seconds representation, so the overflow band is enormous (roughly
/// everything above ~5.8e11 years in seconds) and completely unreachable from
/// any legitimate interval; an `Err` from it can only mean "the number is
/// nonsense", never "the config was rejected unfairly".
///
/// Sub-second values survive the round trip intact -- the conversion keeps
/// nanosecond precision -- which matters because a legitimate
/// `export_deadline: 0.5` must not be rounded to zero.
fn seconds_to_duration(seconds: f64, path: &str) -> Result<StdDuration, ConfigError> {
    if !seconds.is_finite() {
        return Err(invalid(path, "must be a finite number of seconds"));
    }
    if seconds <= 0.0 {
        return Err(invalid(
            path,
            "must be a positive number of seconds (0 means \"never export\"; omit the field \
             to take the default instead)",
        ));
    }
    StdDuration::try_from_secs_f64(seconds).map_err(|_| {
        invalid(
            path,
            "is too large to represent as a duration (the largest interval this proxy accepts \
             for any timing field is 3600s; this value is beyond even a u64-seconds \
             representation)",
        )
    })
}

/// Type URL key Envoy expects for the one `typed_extension_protocol_options`
/// entry we implement: HTTP/1-vs-HTTP/2 selection via `explicit_http_config`.
const HTTP_PROTOCOL_OPTIONS_TYPE: &str = "envoy.extensions.upstreams.http.v3.HttpProtocolOptions";

/// Lower a cluster's `typed_extension_protocol_options` map into the IR's
/// single-dimension [`UpstreamProtocol`]. Envoy keys this map by extension
/// name; we only implement the one entry that selects HTTP/1 vs HTTP/2
/// (`envoy.extensions.upstreams.http.v3.HttpProtocolOptions`), so any other
/// key -- or any of that message's fields we don't model -- is rejected with
/// its full dotted path (AGENTS.md invariant 1) rather than silently ignored.
fn convert_upstream_protocol(
    opts: &std::collections::HashMap<String, prost_types::Any>,
    path: &str,
) -> Result<UpstreamProtocol, ConfigError> {
    if opts.is_empty() {
        return Ok(UpstreamProtocol::Http1); // Envoy default: HTTP/1.1.
    }

    let map_path = format!("{path}.typed_extension_protocol_options");

    // Rust note: `opts` is a `HashMap`, whose iteration order is unspecified;
    // sort the keys first so which key we complain about (and the resulting
    // error) is deterministic across runs rather than depending on hashing.
    let mut keys: Vec<&String> = opts.keys().collect();
    keys.sort();
    for key in keys {
        if key != HTTP_PROTOCOL_OPTIONS_TYPE {
            return Err(unsupported(
                format!("{map_path}[\"{key}\"]"),
                format!("only `{HTTP_PROTOCOL_OPTIONS_TYPE}` is implemented"),
            ));
        }
    }

    let any = &opts[HTTP_PROTOCOL_OPTIONS_TYPE];
    let entry_path = format!("{map_path}[\"{HTTP_PROTOCOL_OPTIONS_TYPE}\"]");
    if type_name(any) != HTTP_PROTOCOL_OPTIONS_TYPE {
        return Err(ConfigError::UnknownTypeUrl {
            field_path: entry_path,
            type_url: any.type_url.clone(),
        });
    }
    let options: upstream_http_v3::HttpProtocolOptions = decode_any(any, &entry_path)?;
    convert_explicit_http_config(&options, &entry_path)
}

/// Read the `explicit_http_config` oneof out of a decoded `HttpProtocolOptions`
/// and map its `protocol_config` oneof to [`UpstreamProtocol`]. The other two
/// top-level oneof branches (`use_downstream_protocol_config`, `auto_config`)
/// and HTTP/3 are already rejected by the surface walk's allowlist for this
/// message (see `allowed_fields`); this function only has to handle the one
/// branch that's on the supported surface.
fn convert_explicit_http_config(
    options: &upstream_http_v3::HttpProtocolOptions,
    path: &str,
) -> Result<UpstreamProtocol, ConfigError> {
    use upstream_http_v3::http_protocol_options::explicit_http_config::ProtocolConfig;
    use upstream_http_v3::http_protocol_options::UpstreamProtocolOptions;

    let explicit = match &options.upstream_protocol_options {
        Some(UpstreamProtocolOptions::ExplicitHttpConfig(explicit)) => explicit,
        _ => {
            return Err(unsupported(
                format!("{path}.explicit_http_config"),
                "only `explicit_http_config` is implemented (not \
                 `use_downstream_protocol_config` or `auto_config`)",
            ))
        }
    };

    match &explicit.protocol_config {
        Some(ProtocolConfig::HttpProtocolOptions(_)) => Ok(UpstreamProtocol::Http1),
        Some(ProtocolConfig::Http2ProtocolOptions(_)) => Ok(UpstreamProtocol::Http2),
        Some(ProtocolConfig::Http3ProtocolOptions(_)) => Err(unsupported(
            format!("{path}.explicit_http_config.http3_protocol_options"),
            "HTTP/3 upstreams are not implemented",
        )),
        None => Err(invalid(
            format!("{path}.explicit_http_config"),
            "explicit_http_config requires one of http_protocol_options or \
             http2_protocol_options",
        )),
    }
}

/// S5: lower Envoy's repeated, priority-tagged `thresholds` list to the IR's
/// flat two-bucket shape. A priority absent from the list keeps Envoy's
/// documented defaults; a bucket with an explicit entry defaults only the
/// *fields* the entry left unset (Envoy's `UInt32Value` semantics: absent
/// means "use the default", not zero).
fn convert_circuit_breakers(
    cb: &Option<cluster_v3::CircuitBreakers>,
    path: &str,
) -> Result<CircuitBreakers, ConfigError> {
    let Some(cb) = cb else {
        return Ok(CircuitBreakers::default());
    };

    // Rust note: `Option<CircuitBreakerThresholds>` per bucket lets us detect
    // a *second* thresholds entry for the same priority (Envoy takes the
    // first; we reject the config outright rather than silently pick one).
    let mut default_bucket: Option<CircuitBreakerThresholds> = None;
    let mut high_bucket: Option<CircuitBreakerThresholds> = None;

    for (i, t) in cb.thresholds.iter().enumerate() {
        let t_path = format!("{path}.circuit_breakers.thresholds[{i}]");
        let retry_budget = t
            .retry_budget
            .as_ref()
            .map(|budget| {
                let budget_percent = budget
                    .budget_percent
                    .as_ref()
                    .map(|percent| percent.value)
                    .unwrap_or(20.0);
                if !budget_percent.is_finite() || !(0.0..=100.0).contains(&budget_percent) {
                    return Err(invalid(
                        format!("{t_path}.retry_budget.budget_percent.value"),
                        "must be a finite percentage in the range 0 through 100",
                    ));
                }
                Ok(RetryBudget {
                    budget_percent,
                    min_retry_concurrency: budget.min_retry_concurrency.unwrap_or(3),
                })
            })
            .transpose()?;
        let thresholds = CircuitBreakerThresholds {
            max_connections: t
                .max_connections
                .unwrap_or(CircuitBreakerThresholds::ENVOY_DEFAULT.max_connections),
            max_pending_requests: t
                .max_pending_requests
                .unwrap_or(CircuitBreakerThresholds::ENVOY_DEFAULT.max_pending_requests),
            max_requests: t
                .max_requests
                .unwrap_or(CircuitBreakerThresholds::ENVOY_DEFAULT.max_requests),
            max_retries: t
                .max_retries
                .unwrap_or(CircuitBreakerThresholds::ENVOY_DEFAULT.max_retries),
            retry_budget,
        };

        use core_v3::RoutingPriority;
        match RoutingPriority::try_from(t.priority) {
            Ok(RoutingPriority::Default) => {
                if default_bucket.replace(thresholds).is_some() {
                    return Err(invalid(
                        format!("{t_path}.priority"),
                        "duplicate `DEFAULT` priority circuit breaker thresholds",
                    ));
                }
            }
            Ok(RoutingPriority::High) => {
                if high_bucket.replace(thresholds).is_some() {
                    return Err(invalid(
                        format!("{t_path}.priority"),
                        "duplicate `HIGH` priority circuit breaker thresholds",
                    ));
                }
            }
            Err(_) => {
                return Err(invalid(
                    format!("{t_path}.priority"),
                    format!("unknown routing priority `{}`", t.priority),
                ))
            }
        }
    }

    Ok(CircuitBreakers {
        default: default_bucket.unwrap_or(CircuitBreakerThresholds::ENVOY_DEFAULT),
        high: high_bucket.unwrap_or(CircuitBreakerThresholds::ENVOY_DEFAULT),
    })
}

/// S6: lower Envoy's repeated `health_checks` to the IR's singular
/// `HealthCheckIR` -- see that type's doc for why more than one is rejected
/// rather than silently narrowed to the first.
fn convert_health_check(
    health_checks: &[core_v3::HealthCheck],
    path: &str,
) -> Result<Option<HealthCheckIR>, ConfigError> {
    if health_checks.is_empty() {
        return Ok(None);
    }
    if health_checks.len() > 1 {
        return Err(unsupported(
            format!("{path}.health_checks[1]"),
            "only one health check per cluster is implemented; running the first while \
             ignoring the rest would silently approximate the config",
        ));
    }
    let hc = &health_checks[0];
    let hc_path = format!("{path}.health_checks[0]");

    // Envoy's own PGV rules mark all four required (`duration.required` on
    // `timeout`/`interval`, `message.required` on the two thresholds); this
    // duplicates that check rather than leaning on it so the error here
    // names the field's own path even if a caller ever reaches this function
    // without having run PGV first (same defensiveness as `endpoint.
    // ok_or_else` above in `convert_endpoint`).
    let timeout = to_std_duration(
        hc.timeout
            .as_ref()
            .ok_or_else(|| invalid(format!("{hc_path}.timeout"), "timeout is required"))?,
        &format!("{hc_path}.timeout"),
    )?;
    let interval = to_std_duration(
        hc.interval
            .as_ref()
            .ok_or_else(|| invalid(format!("{hc_path}.interval"), "interval is required"))?,
        &format!("{hc_path}.interval"),
    )?;
    let interval_jitter = match &hc.interval_jitter {
        Some(d) => to_std_duration(d, &format!("{hc_path}.interval_jitter"))?,
        None => StdDuration::ZERO,
    };
    let unhealthy_threshold = hc.unhealthy_threshold.ok_or_else(|| {
        invalid(
            format!("{hc_path}.unhealthy_threshold"),
            "unhealthy_threshold is required",
        )
    })?;
    let healthy_threshold = hc.healthy_threshold.ok_or_else(|| {
        invalid(
            format!("{hc_path}.healthy_threshold"),
            "healthy_threshold is required",
        )
    })?;
    let no_traffic_interval = match &hc.no_traffic_interval {
        Some(d) => to_std_duration(d, &format!("{hc_path}.no_traffic_interval"))?,
        None => DEFAULT_NO_TRAFFIC_INTERVAL,
    };

    use core_v3::health_check::HealthChecker;
    let kind = match &hc.health_checker {
        Some(HealthChecker::HttpHealthCheck(http)) => {
            convert_http_health_check(http, &format!("{hc_path}.http_health_check"))?
        }
        Some(HealthChecker::TcpHealthCheck(tcp)) => {
            convert_tcp_health_check(tcp, &format!("{hc_path}.tcp_health_check"))?
        }
        // Both rejected outright rather than lowered to a stub that always
        // reports healthy -- see `HealthCheckKindIR`'s doc. Reachable
        // despite the surface walk allowing these two field names through
        // (see the `allowed_fields` comment above `"envoy.config.core.v3.
        // HealthCheck"`): this match runs after that walk and gives the
        // operator-facing reason instead of the walk's generic text.
        Some(HealthChecker::GrpcHealthCheck(_)) => {
            return Err(unsupported(
                format!("{hc_path}.grpc_health_check"),
                "gRPC health checks are not implemented",
            ))
        }
        Some(HealthChecker::CustomHealthCheck(_)) => {
            return Err(unsupported(
                format!("{hc_path}.custom_health_check"),
                "custom health checks are not implemented",
            ))
        }
        None => {
            return Err(invalid(
                &hc_path,
                "a health_checker is required (http_health_check or tcp_health_check)",
            ))
        }
    };

    Ok(Some(HealthCheckIR {
        interval,
        timeout,
        interval_jitter,
        unhealthy_threshold,
        healthy_threshold,
        no_traffic_interval,
        kind,
    }))
}

fn convert_http_health_check(
    http: &core_v3::health_check::HttpHealthCheck,
    path: &str,
) -> Result<HealthCheckKindIR, ConfigError> {
    let mut expected_statuses = Vec::new();
    for (i, range) in http.expected_statuses.iter().enumerate() {
        expand_status_range(
            range,
            &format!("{path}.expected_statuses[{i}]"),
            &mut expected_statuses,
        )?;
    }
    Ok(HealthCheckKindIR::Http {
        path: http.path.clone(),
        expected_statuses,
        host: if http.host.is_empty() {
            None
        } else {
            Some(http.host.clone())
        },
    })
}

/// Expand one half-open `Int64Range` (start inclusive, end exclusive -- see
/// the proto's own doc on `Int64Range`) into `HealthCheckKindIR::Http`'s flat
/// `u16` list. Rejects a range outside `[100, 600)` -- the only statuses a
/// health check response can legally carry -- or with `end <= start`, since
/// either would otherwise produce a `u16` that does not correspond to a real
/// status code.
fn expand_status_range(
    range: &type_v3::Int64Range,
    path: &str,
    out: &mut Vec<u16>,
) -> Result<(), ConfigError> {
    if range.end <= range.start {
        return Err(invalid(
            path,
            format!(
                "range end ({}) must be greater than start ({})",
                range.end, range.start
            ),
        ));
    }
    if range.start < 100 || range.end > 600 {
        return Err(invalid(
            path,
            format!(
                "range [{}, {}) falls outside the only statuses a health check response can \
                 carry, [100, 600)",
                range.start, range.end
            ),
        ));
    }
    // Rust note: bounds are already proven to fit `u16` (100..=599) by the
    // checks above, so this cast never truncates.
    out.extend((range.start..range.end).map(|status| status as u16));
    Ok(())
}

fn convert_tcp_health_check(
    tcp: &core_v3::health_check::TcpHealthCheck,
    path: &str,
) -> Result<HealthCheckKindIR, ConfigError> {
    let send = match &tcp.send {
        Some(p) => convert_payload(p, &format!("{path}.send"))?,
        None => Vec::new(),
    };
    if tcp.receive.len() > 1 {
        return Err(unsupported(
            format!("{path}.receive[1]"),
            "only one `receive` payload per TCP health check is implemented; the IR carries a \
             single `expect`",
        ));
    }
    let expect = match tcp.receive.first() {
        Some(p) => convert_payload(p, &format!("{path}.receive[0]"))?,
        None => Vec::new(),
    };
    Ok(HealthCheckKindIR::Tcp { send, expect })
}

/// `Payload.text` is HEX-ENCODED (Envoy's own doc: `"000000FF"` decodes to
/// four bytes), never raw text; `Payload.binary` is already raw bytes.
/// Getting this backwards silently changes what a TCP health check sends or
/// matches without any error -- exactly AGENTS.md invariant 1's failure mode.
fn convert_payload(
    payload: &core_v3::health_check::Payload,
    path: &str,
) -> Result<Vec<u8>, ConfigError> {
    use core_v3::health_check::payload::Payload as PayloadKind;
    match &payload.payload {
        Some(PayloadKind::Text(hex)) => decode_hex_payload(hex, &format!("{path}.text")),
        Some(PayloadKind::Binary(bytes)) => Ok(bytes.clone()),
        None => Err(invalid(path, "payload is required (text or binary)")),
    }
}

fn decode_hex_payload(hex: &str, path: &str) -> Result<Vec<u8>, ConfigError> {
    // Rust note: work over bytes rather than `&str` slicing -- `hex[i..i+2]`
    // would panic on a non-ASCII input that lands a byte index off a char
    // boundary, before we ever get the chance to report an ordinary
    // "not valid hex" error instead.
    let bytes = hex.as_bytes();
    if !hex.is_ascii() || !bytes.len().is_multiple_of(2) {
        return Err(invalid(
            path,
            format!(
                "`{hex}` is not valid hex (must be ASCII with an even number of digits, e.g. \
                 \"000000FF\")"
            ),
        ));
    }
    bytes
        .chunks(2)
        .map(|pair| {
            // `str::from_utf8` cannot fail: `is_ascii` above already proved
            // every byte is a single-byte UTF-8 char boundary.
            let digits = std::str::from_utf8(pair).expect("ascii-checked above");
            u8::from_str_radix(digits, 16)
                .map_err(|_| invalid(path, format!("`{hex}` is not valid hex")))
        })
        .collect()
}

/// S6: lower `envoy.config.cluster.v3.OutlierDetection` to the IR's
/// [`OutlierDetectionIR`]. `None` in → `None` out (no passive ejection).
/// A present-but-empty block means **all S6 defaults**, never Rust zeros --
/// a zero `max_ejection_percent` or `enforcing_consecutive_5xx` would
/// silently disable ejection, so every field falls back to
/// [`OutlierDetectionIR::ENVOY_DEFAULT`], not to `0`.
///
/// Two of the enforcing-percent defaults are **0**, not 100 --
/// `enforcing_consecutive_gateway_failure` and `enforcing_failure_percentage`
/// -- so those two detectors are tracked but never eject out of the box. That
/// is Envoy's own default and the one most implementations get wrong; it is
/// preserved here, not "helpfully" raised to 100.
fn convert_outlier_detection(
    od: Option<&cluster_v3::OutlierDetection>,
    path: &str,
) -> Result<Option<OutlierDetectionIR>, ConfigError> {
    let Some(od) = od else {
        return Ok(None);
    };
    let od_path = format!("{path}.outlier_detection");
    let d = OutlierDetectionIR::ENVOY_DEFAULT;

    // Only `false` (Envoy's own default) is implemented -- see the IR type's
    // doc and `OutlierDetectionConfig::split_external_local_origin_errors`.
    // `true` would need a whole separate local-origin failure axis the
    // detector folds into the 5xx path instead, so it is rejected rather
    // than accepted-and-ignored (AGENTS.md invariant 1).
    if od.split_external_local_origin_errors {
        return Err(unsupported(
            format!("{od_path}.split_external_local_origin_errors"),
            "only `false` is implemented: local-origin failures are folded into the 5xx path, \
             not tracked as a separate axis",
        ));
    }

    let interval = match &od.interval {
        Some(v) => to_std_duration(v, &format!("{od_path}.interval"))?,
        None => d.interval,
    };
    let base_ejection_time = match &od.base_ejection_time {
        Some(v) => to_std_duration(v, &format!("{od_path}.base_ejection_time"))?,
        None => d.base_ejection_time,
    };
    // Envoy documents `max_ejection_time` as defaulting to
    // `max(300s, base_ejection_time)`, and a configured value below the base
    // is meaningless (an ejection can never last less than its own first
    // step), so clamp up to `base_ejection_time` either way. Silently letting
    // `max < base` through would mean "every ejection lasts base, not the
    // configured max" -- a value that reads as configured but is not honored.
    let max_ejection_time = match &od.max_ejection_time {
        Some(v) => to_std_duration(v, &format!("{od_path}.max_ejection_time"))?,
        None => d.max_ejection_time,
    }
    .max(base_ejection_time);

    Ok(Some(OutlierDetectionIR {
        interval,
        base_ejection_time,
        max_ejection_time,
        max_ejection_percent: percent(
            od.max_ejection_percent,
            d.max_ejection_percent,
            &format!("{od_path}.max_ejection_percent"),
        )?,
        always_eject_one_host: od.always_eject_one_host.unwrap_or(d.always_eject_one_host),
        consecutive_5xx: od.consecutive_5xx.unwrap_or(d.consecutive_5xx),
        enforcing_consecutive_5xx: percent(
            od.enforcing_consecutive_5xx,
            d.enforcing_consecutive_5xx,
            &format!("{od_path}.enforcing_consecutive_5xx"),
        )?,
        consecutive_gateway_failure: od
            .consecutive_gateway_failure
            .unwrap_or(d.consecutive_gateway_failure),
        enforcing_consecutive_gateway_failure: percent(
            od.enforcing_consecutive_gateway_failure,
            d.enforcing_consecutive_gateway_failure,
            &format!("{od_path}.enforcing_consecutive_gateway_failure"),
        )?,
        success_rate_min_hosts: od
            .success_rate_minimum_hosts
            .unwrap_or(d.success_rate_min_hosts),
        success_rate_request_volume: od
            .success_rate_request_volume
            .unwrap_or(d.success_rate_request_volume),
        success_rate_stdev_factor: od
            .success_rate_stdev_factor
            .unwrap_or(d.success_rate_stdev_factor),
        enforcing_success_rate: percent(
            od.enforcing_success_rate,
            d.enforcing_success_rate,
            &format!("{od_path}.enforcing_success_rate"),
        )?,
        failure_percentage_threshold: percent(
            od.failure_percentage_threshold,
            d.failure_percentage_threshold,
            &format!("{od_path}.failure_percentage_threshold"),
        )?,
        enforcing_failure_percentage: percent(
            od.enforcing_failure_percentage,
            d.enforcing_failure_percentage,
            &format!("{od_path}.enforcing_failure_percentage"),
        )?,
        failure_percentage_min_hosts: od
            .failure_percentage_minimum_hosts
            .unwrap_or(d.failure_percentage_min_hosts),
        failure_percentage_request_volume: od
            .failure_percentage_request_volume
            .unwrap_or(d.failure_percentage_request_volume),
        uneject_on_healthy_active_hc: od
            .successful_active_health_check_uneject_host
            .unwrap_or(d.uneject_on_healthy_active_hc),
    }))
}

/// A percent field (0–100) that the IR holds as `u8`. `None` → `default`;
/// a value above 100 is rejected with its path rather than truncated, since
/// the proto carries it as `u32` and a silent wrap would mean an
/// enforcement percentage the operator never wrote.
fn percent(value: Option<u32>, default: u8, path: &str) -> Result<u8, ConfigError> {
    match value {
        None => Ok(default),
        Some(v) if v <= 100 => Ok(v as u8),
        Some(v) => Err(invalid(
            path,
            format!("must be a percentage in [0, 100], got {v}"),
        )),
    }
}

/// Namespace key this proxy uses to carry operator-facing labels through
/// `LbEndpoint.metadata.filter_metadata` -- see `EndpointIR::metadata`'s doc
/// comment in `ir.rs` for the full design.
const ENDPOINT_METADATA_KEY: &str = "io.llmproxy.endpoint";

/// Lower `LbEndpoint.metadata.filter_metadata["io.llmproxy.endpoint"]` into
/// [`EndpointIR::metadata`]. Every field's value must be a plain string; any
/// other shape (a number, bool, nested object, or list) is a hard error
/// naming its full dotted path rather than a stringified guess -- an
/// operator who wrote `weight: 5` there meant something specific, and this
/// isn't the field that carries LB weight (`load_balancing_weight` is).
///
/// Unlike [`convert_provider_auth_metadata`], which leaves every namespace
/// other than its own alone, EVERY namespace other than ours is refused
/// outright here, by dotted path. `envoy.lb` is named explicitly: it is
/// Envoy's own LB subset-routing selector, and this proxy implements no
/// subset routing, so silently accepting it into a map nothing routes on
/// would leave an operator's exclusion list installed but never enforced --
/// AGENTS.md invariant 1's exact failure mode. Any third namespace gets the same
/// refusal with a plainer "unknown namespace" message.
fn convert_endpoint_metadata(
    metadata: Option<&core_v3::Metadata>,
    path: &str,
) -> Result<std::collections::BTreeMap<String, String>, ConfigError> {
    let Some(metadata) = metadata else {
        return Ok(std::collections::BTreeMap::new());
    };
    let filter_metadata_path = format!("{path}.metadata.filter_metadata");

    // Rust note: `filter_metadata` is a `HashMap`, so sort keys before
    // reporting one to keep the error deterministic across runs.
    let mut namespaces: Vec<&String> = metadata.filter_metadata.keys().collect();
    namespaces.sort();
    for ns in namespaces {
        if ns == ENDPOINT_METADATA_KEY {
            continue;
        }
        let ns_path = format!("{filter_metadata_path}[\"{ns}\"]");
        if ns == "envoy.lb" {
            return Err(unsupported(
                ns_path,
                "`envoy.lb` is Envoy's LB subset-routing selector; this proxy implements no \
                 subset routing, so accepting it here would silently send traffic to \
                 endpoints the operator meant to exclude",
            ));
        }
        return Err(unsupported(
            ns_path,
            format!("unknown metadata namespace; only `{ENDPOINT_METADATA_KEY}` is supported"),
        ));
    }

    let Some(fields) = metadata.filter_metadata.get(ENDPOINT_METADATA_KEY) else {
        return Ok(std::collections::BTreeMap::new());
    };
    let ns_path = format!("{filter_metadata_path}[\"{ENDPOINT_METADATA_KEY}\"]");

    // Rust note: same determinism reason as the namespace sort above.
    let mut keys: Vec<&String> = fields.fields.keys().collect();
    keys.sort();
    let mut out = std::collections::BTreeMap::new();
    for key in keys {
        let value = &fields.fields[key];
        match &value.kind {
            Some(prost_types::value::Kind::StringValue(v)) => {
                out.insert(key.clone(), v.clone());
            }
            _ => return Err(invalid(format!("{ns_path}.{key}"), "must be a string")),
        }
    }
    Ok(out)
}

fn convert_endpoint(
    lbe: &endpoint_v3::LbEndpoint,
    priority: u32,
    discovery: DiscoveryType,
    path: &str,
) -> Result<EndpointIR, ConfigError> {
    use endpoint_v3::lb_endpoint::HostIdentifier;
    let endpoint = match &lbe.host_identifier {
        Some(HostIdentifier::Endpoint(e)) => e,
        Some(HostIdentifier::EndpointName(_)) => {
            return Err(unsupported(
                format!("{path}.endpoint_name"),
                "named endpoints are not implemented",
            ))
        }
        None => return Err(invalid(path, "endpoint is required")),
    };
    let addr = endpoint
        .address
        .as_ref()
        .ok_or_else(|| invalid(format!("{path}.endpoint"), "address is required"))?;
    let (host, port) = socket_host_port(addr, &format!("{path}.endpoint.address"))?;
    // STATIC and EDS both require a literal IP, for two different reasons
    // that land in the same place.
    //
    // STATIC: nothing ever resolves a STATIC cluster's own endpoints, so a
    // hostname here would silently never connect.
    //
    // EDS: an EDS-delivered endpoint is consumed by
    // `ClusterManager::accept_eds_update`, which builds hosts through
    // `discovery::static_hosts` -- and that does no name resolution either.
    // Accepting a name here would not make it work; it would only move the
    // failure from a config-time error carrying a dotted path to a per-update
    // runtime `io::Error` on every EDS push, which is AGENTS.md invariant 1's exact
    // shape. Envoy's EDS wire format does permit a hostname, so this is a
    // limitation of what we can currently do with one, and the message says
    // so rather than claiming the wire format forbids it.
    if matches!(discovery, DiscoveryType::Static | DiscoveryType::Eds)
        && host.parse::<IpAddr>().is_err()
    {
        let why = if discovery == DiscoveryType::Static {
            "STATIC clusters require IPs (use STRICT_DNS or LOGICAL_DNS for hostnames)"
        } else {
            "EDS-delivered endpoints require IPs -- the endpoints an EDS response carries are \
             installed without name resolution, so a hostname here would never connect"
        };
        return Err(invalid(
            format!("{path}.endpoint.address.socket_address.address"),
            format!("`{host}` is not an IP address; {why}"),
        ));
    }
    Ok(EndpointIR {
        metadata: convert_endpoint_metadata(lbe.metadata.as_ref(), path)?,
        host,
        port,
        weight: lbe.load_balancing_weight.unwrap_or(1),
        priority,
    })
}

fn convert_upstream_tls(
    ts: &core_v3::TransportSocket,
    path: &str,
) -> Result<UpstreamTlsSpec, ConfigError> {
    use core_v3::transport_socket::ConfigType;
    let any = match &ts.config_type {
        Some(ConfigType::TypedConfig(any)) => any,
        None => return Err(invalid(path, "transport_socket requires typed_config")),
    };
    let cfg_path = format!("{path}.typed_config");
    if type_name(any) != UPSTREAM_TLS_TYPE {
        return Err(ConfigError::UnknownTypeUrl {
            field_path: cfg_path,
            type_url: any.type_url.clone(),
        });
    }
    let ctx: tls_v3::UpstreamTlsContext = decode_any(any, &cfg_path)?;

    // Rust note: `Option::as_ref()...unwrap_or(&default)` lets the (common,
    // params, certs, validation) conversions below run uniformly whether or
    // not `common_tls_context` was set at all — Envoy treats an absent one as
    // "everything at its default", same as an empty one.
    let empty_common = tls_v3::CommonTlsContext::default();
    let common = ctx.common_tls_context.as_ref().unwrap_or(&empty_common);
    let common_path = format!("{cfg_path}.common_tls_context");

    let params = convert_tls_params(
        common.tls_params.as_ref(),
        &format!("{common_path}.tls_params"),
        false,
    )?;
    let client_certificate = convert_upstream_certificate(
        &common.tls_certificates,
        &format!("{common_path}.tls_certificates"),
    )?;
    // Envoy parity: no validation_context configured means the upstream
    // certificate is NOT verified at all — dangerous, but that's the
    // documented default, and the IR's doc comment says as much.
    let (validation, validation_sds_name) = convert_validation_context(common, &common_path)?;
    if validation_sds_name.is_some() {
        return Err(unsupported(
            format!("{common_path}.validation_context_sds_secret_config"),
            "SDS-delivered validation contexts are implemented only for downstream TLS",
        ));
    }

    Ok(UpstreamTlsSpec {
        sni: (!ctx.sni.is_empty()).then(|| ctx.sni.clone()),
        params,
        alpn_protocols: common.alpn_protocols.clone(),
        client_certificate,
        validation,
    })
}

// -------------------------------------------------------------------- routes --

fn convert_route_table(
    rc: &route_v3::RouteConfiguration,
    path: &str,
) -> Result<RouteTable, ConfigError> {
    let mut vhosts = Vec::new();
    for (i, vh) in rc.virtual_hosts.iter().enumerate() {
        let vh_path = format!("{path}.virtual_hosts[{i}]");
        let mut routes = Vec::new();
        for (j, r) in vh.routes.iter().enumerate() {
            // Rust note: `Arc`'d here (not a bare `RouteEntry`) so the S2.8
            // route cache in `proxy-http`'s frozen filter API can hand out
            // `Arc<RouteEntry>` clones (see the field doc on
            // `VirtualHostIR::routes`).
            routes.push(Arc::new(convert_route(
                r,
                &format!("{vh_path}.routes[{j}]"),
                vh.include_request_attempt_count,
                vh.include_attempt_count_in_response,
            )?));
        }
        let vh_typed_per_filter_config = convert_typed_per_filter_config(
            &vh.typed_per_filter_config,
            &format!("{vh_path}.typed_per_filter_config"),
        )?;
        vhosts.push(VirtualHostIR {
            name: vh.name.clone(),
            domains: vh.domains.clone(),
            routes,
            typed_per_filter_config: vh_typed_per_filter_config,
        });
    }
    let rc_typed_per_filter_config = convert_typed_per_filter_config(
        &rc.typed_per_filter_config,
        &format!("{path}.typed_per_filter_config"),
    )?;
    for (i, vhost) in vhosts.iter().enumerate() {
        for (j, route) in vhost.routes.iter().enumerate() {
            let levels = [
                &rc_typed_per_filter_config,
                &vhost.typed_per_filter_config,
                &route.typed_per_filter_config,
            ];
            let names: std::collections::BTreeSet<_> =
                levels.iter().flat_map(|level| level.keys()).collect();
            for name in names {
                let mut context = BTreeMap::new();
                for level in levels {
                    if let Some(per) = level.get(name) {
                        if per.disabled {
                            context.clear();
                            continue;
                        }
                        match &per.ext_authz {
                            Some(crate::authorization::ExtAuthzPerRoute::Check {
                                context_extensions,
                            }) => context.extend(context_extensions.clone()),
                            Some(crate::authorization::ExtAuthzPerRoute::Disabled) => {
                                context.clear()
                            }
                            None => {}
                        }
                    }
                }
                if context.len() > 64
                    || context
                        .iter()
                        .map(|(k, v)| k.len() + v.len())
                        .sum::<usize>()
                        > crate::authorization::MAX_MUTATION_BYTES
                {
                    return Err(invalid(format!("{path}.virtual_hosts[{i}].routes[{j}].typed_per_filter_config[{name}].check_settings.context_extensions"), "merged context extensions exceed limits"));
                }
            }
        }
    }
    RouteTable::new(rc.name.clone(), vhosts, rc_typed_per_filter_config).map_err(|dup| {
        invalid(
            format!("{path}.virtual_hosts"),
            format!("duplicate domain `{}`", dup.0),
        )
    })
}

fn convert_route(
    r: &route_v3::Route,
    path: &str,
    include_request_attempt_count: bool,
    include_attempt_count_in_response: bool,
) -> Result<RouteEntry, ConfigError> {
    let m = r
        .r#match
        .as_ref()
        .ok_or_else(|| invalid(format!("{path}.match"), "route match is required"))?;
    let matcher = convert_route_match(m, &format!("{path}.match"))?;

    use route_v3::route::Action;
    let action = match &r.action {
        Some(Action::Route(ra)) => {
            RouteActionIR::Forward(convert_route_action(ra, &format!("{path}.route"))?)
        }
        Some(Action::Redirect(red)) => RouteActionIR::Redirect(convert_redirect(red)),
        Some(Action::DirectResponse(dr)) => RouteActionIR::DirectResponse {
            status: u16::try_from(dr.status).map_err(|_| {
                invalid(
                    format!("{path}.direct_response.status"),
                    "status out of range",
                )
            })?,
            body: dr
                .body
                .as_ref()
                .map(|ds| convert_direct_response_body(ds, &format!("{path}.direct_response.body")))
                .transpose()?,
        },
        Some(_) => {
            return Err(unsupported(
                path,
                "only route/redirect/direct_response actions are implemented",
            ))
        }
        None => return Err(invalid(path, "route action is required")),
    };

    let mut request_headers_to_add = Vec::new();
    for (i, hvo) in r.request_headers_to_add.iter().enumerate() {
        request_headers_to_add.push(convert_header_mutation(
            hvo,
            &format!("{path}.request_headers_to_add[{i}]"),
        )?);
    }

    let typed_per_filter_config = convert_typed_per_filter_config(
        &r.typed_per_filter_config,
        &format!("{path}.typed_per_filter_config"),
    )?;
    let streaming_strict = convert_streaming_strict_metadata(r.metadata.as_ref(), path)?;

    Ok(RouteEntry {
        name: (!r.name.is_empty()).then(|| r.name.clone()),
        matcher,
        action,
        request_headers_to_add,
        streaming_strict,
        typed_per_filter_config,
        // Rust note: real value assigned in bulk by `RouteTable::new` (via
        // `Arc::get_mut`) once every route in the table has been built --
        // this constructor doesn't know the table-wide ordering yet.
        route_index: 0,
        include_request_attempt_count,
        include_attempt_count_in_response,
    })
}

fn convert_route_match(m: &route_v3::RouteMatch, path: &str) -> Result<RouteMatcher, ConfigError> {
    use route_v3::route_match::PathSpecifier;
    let path_match = match &m.path_specifier {
        Some(PathSpecifier::Prefix(p)) => PathMatch::Prefix(p.clone()),
        Some(PathSpecifier::Path(p)) => PathMatch::Exact(p.clone()),
        Some(PathSpecifier::SafeRegex(re)) => PathMatch::Regex(compile_regex(
            &re.regex,
            &format!("{path}.safe_regex.regex"),
        )?),
        Some(_) => {
            return Err(unsupported(
                path,
                "only prefix/path/safe_regex path matching is implemented",
            ))
        }
        None => return Err(invalid(path, "a path specifier is required")),
    };

    let mut headers = Vec::new();
    for (i, hm) in m.headers.iter().enumerate() {
        headers.push(convert_header_matcher(hm, &format!("{path}.headers[{i}]"))?);
    }

    Ok(RouteMatcher {
        path: path_match,
        // Envoy default: case-sensitive path matching (S1).
        case_sensitive: m.case_sensitive.unwrap_or(true),
        headers,
    })
}

fn convert_header_matcher(
    hm: &route_v3::HeaderMatcher,
    path: &str,
) -> Result<HeaderMatch, ConfigError> {
    use matcher_v3::string_matcher::MatchPattern;
    use route_v3::header_matcher::HeaderMatchSpecifier;
    let kind = match &hm.header_match_specifier {
        Some(HeaderMatchSpecifier::StringMatch(sm)) => {
            let ignore_case = sm.ignore_case;
            match &sm.match_pattern {
                Some(MatchPattern::Exact(v)) => HeaderMatchKind::Exact {
                    value: v.clone(),
                    ignore_case,
                },
                Some(MatchPattern::Prefix(v)) => HeaderMatchKind::Prefix {
                    value: v.clone(),
                    ignore_case,
                },
                Some(MatchPattern::Suffix(v)) => HeaderMatchKind::Suffix {
                    value: v.clone(),
                    ignore_case,
                },
                Some(MatchPattern::SafeRegex(re)) => HeaderMatchKind::Regex(compile_regex(
                    &re.regex,
                    &format!("{path}.string_match.safe_regex.regex"),
                )?),
                Some(_) => {
                    return Err(unsupported(
                        format!("{path}.string_match"),
                        "only exact/prefix/suffix/safe_regex string matching is implemented",
                    ))
                }
                None => {
                    return Err(invalid(
                        format!("{path}.string_match"),
                        "a match pattern is required",
                    ))
                }
            }
        }
        Some(HeaderMatchSpecifier::PresentMatch(p)) => HeaderMatchKind::Present(*p),
        Some(_) => {
            return Err(unsupported(
                path,
                "only string_match/present_match header matching is implemented",
            ))
        }
        None => return Err(invalid(path, "a header match specifier is required")),
    };
    Ok(HeaderMatch {
        name: hm.name.clone(),
        kind,
    })
}

fn convert_route_action(
    ra: &route_v3::RouteAction,
    path: &str,
) -> Result<ForwardAction, ConfigError> {
    use route_v3::route_action::ClusterSpecifier;
    let target = match &ra.cluster_specifier {
        Some(ClusterSpecifier::Cluster(name)) => ForwardTarget::Cluster(name.clone()),
        Some(ClusterSpecifier::ClusterHeader(h)) => ForwardTarget::ClusterHeader(h.clone()),
        Some(ClusterSpecifier::WeightedClusters(wc)) => ForwardTarget::Weighted(
            convert_weighted_clusters(wc, &format!("{path}.weighted_clusters"))?,
        ),
        Some(_) => {
            return Err(unsupported(
                path,
                "only cluster/cluster_header/weighted_clusters targets are implemented",
            ))
        }
        None => return Err(invalid(path, "a cluster specifier is required")),
    };

    // S4: default 15s; explicit 0 disables the total timeout entirely.
    let timeout = match &ra.timeout {
        None => Some(DEFAULT_ROUTE_TIMEOUT),
        Some(d) if is_zero(d) => None,
        Some(d) => Some(to_std_duration(d, &format!("{path}.timeout"))?),
    };
    let idle_timeout = ra
        .idle_timeout
        .as_ref()
        .map(|d| to_std_duration(d, &format!("{path}.idle_timeout")))
        .transpose()?;

    let retry_policy = ra
        .retry_policy
        .as_ref()
        .map(|rp| convert_retry_policy(rp, &format!("{path}.retry_policy")))
        .transpose()?;

    // S3 hedging is deliberately a narrow first increment: Envoy's default
    // one initial request, no probabilistic extra request, and a replay only
    // when the per-try timer fires.  Do not accept the other knobs merely to
    // drop them in the router.
    let hedge_on_per_try_timeout = match ra.hedge_policy.as_ref() {
        None => false,
        Some(hedge) => {
            if hedge
                .initial_requests
                .as_ref()
                .is_some_and(|requests| *requests != 1)
            {
                return Err(unsupported(
                    format!("{path}.hedge_policy.initial_requests"),
                    "only the Envoy default of 1 initial request is implemented",
                ));
            }
            if hedge.additional_request_chance.is_some() {
                return Err(unsupported(
                    format!("{path}.hedge_policy.additional_request_chance"),
                    "probabilistic additional requests are not implemented",
                ));
            }
            hedge.hedge_on_per_try_timeout
        }
    };
    if hedge_on_per_try_timeout {
        let Some(retry) = retry_policy.as_ref() else {
            return Err(invalid(
                format!("{path}.hedge_policy.hedge_on_per_try_timeout"),
                "requires a retry_policy with a per_try_timeout and at least one retry",
            ));
        };
        if retry.per_try_timeout.is_none() || retry.num_retries == 0 {
            return Err(invalid(
                format!("{path}.hedge_policy.hedge_on_per_try_timeout"),
                "requires a retry_policy with a per_try_timeout and at least one retry",
            ));
        }
    }

    Ok(ForwardAction {
        target,
        timeout,
        idle_timeout,
        retry_policy: retry_policy.map(|mut retry| {
            retry.hedge_on_per_try_timeout = hedge_on_per_try_timeout;
            retry
        }),
        host_rewrite_literal: match &ra.host_rewrite_specifier {
            Some(route_v3::route_action::HostRewriteSpecifier::HostRewriteLiteral(h)) => {
                Some(h.clone())
            }
            Some(_) => {
                return Err(unsupported(
                    path,
                    "only host_rewrite_literal host rewriting is implemented",
                ))
            }
            None => None,
        },
        prefix_rewrite: (!ra.prefix_rewrite.is_empty()).then(|| ra.prefix_rewrite.clone()),
    })
}

fn convert_weighted_clusters(
    wc: &route_v3::WeightedCluster,
    path: &str,
) -> Result<WeightedClusters, ConfigError> {
    let mut cumulative = Vec::with_capacity(wc.clusters.len());
    let mut total: u64 = 0;
    for (i, cw) in wc.clusters.iter().enumerate() {
        let weight = u64::from(cw.weight.unwrap_or(0));
        if weight == 0 {
            // Envoy skips zero-weight clusters; we keep the array dense.
            continue;
        }
        total += weight;
        let _ = i;
        cumulative.push((cw.name.clone(), total));
    }
    if total == 0 {
        return Err(invalid(path, "total weight must be greater than 0"));
    }
    Ok(WeightedClusters {
        cumulative,
        total_weight: total,
    })
}

fn convert_retry_policy(
    rp: &route_v3::RetryPolicy,
    path: &str,
) -> Result<RetryPolicyIR, ConfigError> {
    let mut codes = Vec::with_capacity(rp.retriable_status_codes.len());
    for c in &rp.retriable_status_codes {
        codes.push(u16::try_from(*c).map_err(|_| {
            invalid(
                format!("{path}.retriable_status_codes"),
                "status out of range",
            )
        })?);
    }
    // S3.3: absent message => Envoy's defaults (25ms / 250ms). When present,
    // `base_interval` is required by the proto and `max_interval` defaults to
    // 10x the base when unset.
    let retry_back_off = match &rp.retry_back_off {
        None => RetryBackOff::ENVOY_DEFAULT,
        Some(rb) => {
            let base_path = format!("{path}.retry_back_off.base_interval");
            let base_interval = rb
                .base_interval
                .as_ref()
                .ok_or_else(|| invalid(&base_path, "base_interval is required"))
                .and_then(|d| to_std_duration(d, &base_path))?;
            let max_interval = rb
                .max_interval
                .as_ref()
                .map(|d| to_std_duration(d, &format!("{path}.retry_back_off.max_interval")))
                .transpose()?
                .unwrap_or(base_interval * 10);
            RetryBackOff {
                base_interval,
                max_interval,
            }
        }
    };

    // S3.4: proto type is int64 (`host_selection_retry_max_attempts`); Envoy
    // default is 1. Reject negative/overflowing values loudly rather than
    // silently truncating.
    let host_selection_retry_max_attempts = u32::try_from(rp.host_selection_retry_max_attempts)
        .map_err(|_| {
            invalid(
                format!("{path}.host_selection_retry_max_attempts"),
                "must be a non-negative value that fits in u32",
            )
        })?;
    let host_selection_retry_max_attempts = if host_selection_retry_max_attempts == 0 {
        1
    } else {
        host_selection_retry_max_attempts
    };

    // The only retry-host predicate implemented in this build is Envoy's
    // built-in `previous_hosts`.  Do not accept a plugin by name alone: its
    // typed config must name the exact empty message as well, otherwise a
    // future plugin option could be silently discarded.
    const PREVIOUS_HOSTS_NAME: &str = "envoy.retry_host_predicates.previous_hosts";
    const PREVIOUS_HOSTS_TYPE: &str =
        "envoy.extensions.retry.host.previous_hosts.v3.PreviousHostsPredicate";
    let mut avoid_previous_hosts = false;
    for (i, predicate) in rp.retry_host_predicate.iter().enumerate() {
        let predicate_path = format!("{path}.retry_host_predicate[{i}]");
        if predicate.name != PREVIOUS_HOSTS_NAME {
            return Err(unsupported(
                format!("{predicate_path}.name"),
                format!("only `{PREVIOUS_HOSTS_NAME}` is implemented"),
            ));
        }
        let Some(route_v3::retry_policy::retry_host_predicate::ConfigType::TypedConfig(config)) =
            &predicate.config_type
        else {
            return Err(invalid(
                format!("{predicate_path}.typed_config"),
                format!("`{PREVIOUS_HOSTS_NAME}` requires `{PREVIOUS_HOSTS_TYPE}` typed_config"),
            ));
        };
        if type_name(config) != PREVIOUS_HOSTS_TYPE {
            return Err(invalid(
                format!("{predicate_path}.typed_config"),
                format!(
                    "expected `{PREVIOUS_HOSTS_TYPE}`, found `{}`",
                    type_name(config)
                ),
            ));
        }
        // Decode even though the message is currently empty: malformed Any
        // bytes are config errors, not a reason to quietly enable a default.
        let _: proxy_api::envoy::extensions::retry::host::previous_hosts::v3::PreviousHostsPredicate =
            decode_any(config, &format!("{predicate_path}.typed_config"))?;
        avoid_previous_hosts = true;
    }

    // Without a host predicate Envoy has nothing to reattempt, so accepting
    // a higher count would still be a dropped knob.  With `previous_hosts`,
    // HostPicker consumes this exact count on every rejected pick.
    if host_selection_retry_max_attempts > 1 && !avoid_previous_hosts {
        return Err(unsupported(
            format!("{path}.host_selection_retry_max_attempts"),
            "values above 1 require the supported `previous_hosts` retry_host_predicate",
        ));
    }

    let retry_on = RetryOn::parse(&rp.retry_on);

    // AGENTS.md invariant 1. `envoy-ratelimited` retries when the response carries
    // `x-envoy-ratelimited`, a header only a rate-limit filter sets -- and no
    // such filter exists yet, so nothing can ever produce the
    // condition. Accepting the token would mean a config that reads as "retry
    // rate-limited responses" and never retries anything.
    if retry_on.envoy_ratelimited {
        return Err(unsupported(
            format!("{path}.retry_on"),
            "the `envoy-ratelimited` retry trigger is not implemented yet (it fires on the \
             `x-envoy-ratelimited` response header, which no filter sets, because no rate-limit \
             filter exists yet)",
        ));
    }

    Ok(RetryPolicyIR {
        retry_on,
        // S3: Envoy default is 1 retry.
        num_retries: rp.num_retries.unwrap_or(1),
        per_try_timeout: rp
            .per_try_timeout
            .as_ref()
            .map(|d| to_std_duration(d, &format!("{path}.per_try_timeout")))
            .transpose()?,
        hedge_on_per_try_timeout: false,
        retriable_status_codes: codes,
        retry_back_off,
        host_selection_retry_max_attempts,
        avoid_previous_hosts,
    })
}

fn convert_redirect(red: &route_v3::RedirectAction) -> RedirectIR {
    use route_v3::redirect_action::{
        PathRewriteSpecifier, RedirectResponseCode, SchemeRewriteSpecifier,
    };
    let response_code = match RedirectResponseCode::try_from(red.response_code) {
        Ok(RedirectResponseCode::MovedPermanently) | Err(_) => 301,
        Ok(RedirectResponseCode::Found) => 302,
        Ok(RedirectResponseCode::SeeOther) => 303,
        Ok(RedirectResponseCode::TemporaryRedirect) => 307,
        Ok(RedirectResponseCode::PermanentRedirect) => 308,
    };
    RedirectIR {
        host_redirect: (!red.host_redirect.is_empty()).then(|| red.host_redirect.clone()),
        path_redirect: match &red.path_rewrite_specifier {
            Some(PathRewriteSpecifier::PathRedirect(p)) => Some(p.clone()),
            _ => None,
        },
        https_redirect: matches!(
            red.scheme_rewrite_specifier,
            Some(SchemeRewriteSpecifier::HttpsRedirect(true))
        ),
        response_code,
    }
}

fn convert_header_mutation(
    hvo: &core_v3::HeaderValueOption,
    path: &str,
) -> Result<HeaderMutation, ConfigError> {
    use core_v3::header_value_option::HeaderAppendAction as ProtoAction;
    let header = hvo
        .header
        .as_ref()
        .ok_or_else(|| invalid(path, "header is required"))?;
    let action = match ProtoAction::try_from(hvo.append_action) {
        Ok(ProtoAction::AppendIfExistsOrAdd) | Err(_) => HeaderAppendAction::AppendIfExistsOrAdd,
        Ok(ProtoAction::AddIfAbsent) => HeaderAppendAction::AddIfAbsent,
        Ok(ProtoAction::OverwriteIfExistsOrAdd) => HeaderAppendAction::OverwriteIfExistsOrAdd,
        Ok(ProtoAction::OverwriteIfExists) => HeaderAppendAction::OverwriteIfExists,
    };
    Ok(HeaderMutation {
        key: header.key.clone(),
        value: header.value.clone(),
        action,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_response_file_body_is_loaded_during_lowering() {
        let path = std::env::temp_dir().join(format!(
            "llmproxy-direct-response-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock must be after UNIX_EPOCH")
                .as_nanos()
        ));
        std::fs::write(&path, "file response").expect("test body must be writable");

        let source = core_v3::DataSource {
            specifier: Some(core_v3::data_source::Specifier::Filename(
                path.to_string_lossy().into_owned(),
            )),
            ..Default::default()
        };
        let body = convert_direct_response_body(&source, "routes[0].direct_response.body")
            .expect("file body must load during lowering");

        assert_eq!(body, DataSourceIR::Inline("file response".to_string()));
        std::fs::remove_file(path).expect("test body must be removable");
    }
}
