//! WP-05: proto -> IR conversion ("lowering").
//!
//! Two passes over a loaded bootstrap:
//!
//! 1. **Surface check** (dynamic): walk every SET field reflectively and
//!    reject any field outside the supported surface with its full dotted
//!    path. This is ground rule #2's teeth — a field we have not implemented
//!    can never be silently ignored, and a proto upgrade that adds fields
//!    fails loudly instead of drifting.
//! 2. **Typed conversion**: build the [`crate::ir`] types from the typed
//!    protos, pre-computing matchers (S1 domain index, compiled regexes,
//!    weighted-cluster cumulative arrays) so the hot path never does it.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use prost_reflect::{DynamicMessage, ReflectMessage, Value};
use proxy_api::envoy::config::bootstrap::v3::Bootstrap;
use proxy_api::envoy::config::cluster::v3 as cluster_v3;
use proxy_api::envoy::config::core::v3 as core_v3;
use proxy_api::envoy::config::endpoint::v3 as endpoint_v3;
use proxy_api::envoy::config::listener::v3 as listener_v3;
use proxy_api::envoy::config::route::v3 as route_v3;
use proxy_api::envoy::extensions::filters::listener::tls_inspector::v3 as tls_inspector_v3;
use proxy_api::envoy::extensions::filters::network::http_connection_manager::v3 as hcm_v3;
use proxy_api::envoy::extensions::filters::network::tcp_proxy::v3 as tcp_proxy_v3;
use proxy_api::envoy::extensions::transport_sockets::tls::v3 as tls_v3;
use proxy_api::envoy::r#type::matcher::v3 as matcher_v3;

use crate::error::ConfigError;
use crate::ir::*;
use crate::loader::LoadedBootstrap;

/// Build the immutable IR snapshot from a loaded bootstrap. This is the only
/// door between protobuf-land and the data plane (ground rule #3).
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

    let Some(sr) = &b.static_resources else {
        return Ok(snapshot);
    };

    for (i, l) in sr.listeners.iter().enumerate() {
        let path = format!("static_resources.listeners[{i}]");
        let ir = convert_listener(l, &path)?;
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
    Ok(snapshot)
}

// ------------------------------------------------------------ surface check --

/// Fields we currently map to IR, per message type. A message type absent from
/// this table is either a leaf we map wholesale or is only reachable through
/// checked parents; a listed type rejects every set field not named.
fn allowed_fields(message: &str) -> Option<&'static [&'static str]> {
    Some(match message {
        "envoy.config.bootstrap.v3.Bootstrap" => &["node", "admin", "static_resources"],
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
        ],
        "envoy.config.listener.v3.ListenerFilter" => &["name", "typed_config"],
        "envoy.config.listener.v3.FilterChain" => {
            &["name", "filter_chain_match", "filters", "transport_socket"]
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
            "connect_timeout",
            "lb_policy",
            "load_assignment",
            "transport_socket",
            "per_connection_buffer_limit_bytes",
        ],
        "envoy.config.endpoint.v3.ClusterLoadAssignment" => &["cluster_name", "endpoints"],
        "envoy.config.endpoint.v3.LocalityLbEndpoints" => &["lb_endpoints", "priority"],
        "envoy.config.endpoint.v3.LbEndpoint" => &["endpoint", "load_balancing_weight"],
        "envoy.config.endpoint.v3.Endpoint" => &["address"],
        "envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy" => &[
            "stat_prefix",
            "cluster",
            "idle_timeout",
            "max_connect_attempts",
        ],
        "envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager" => {
            &["stat_prefix", "route_config", "http_filters"]
        }
        "envoy.extensions.filters.network.http_connection_manager.v3.HttpFilter" => {
            &["name", "typed_config"]
        }
        "envoy.extensions.filters.http.router.v3.Router" => &[],
        "envoy.config.route.v3.RouteConfiguration" => &["name", "virtual_hosts"],
        "envoy.config.route.v3.VirtualHost" => &["name", "domains", "routes"],
        "envoy.config.route.v3.Route" => &[
            "name",
            "match",
            "route",
            "redirect",
            "direct_response",
            "request_headers_to_add",
        ],
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
            "validation_context",
            "alpn_protocols",
        ],
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

// ---------------------------------------------------------------- listeners --

const TCP_PROXY_TYPE: &str = "envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy";
const HCM_TYPE: &str =
    "envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager";
const ROUTER_TYPE: &str = "envoy.extensions.filters.http.router.v3.Router";
const DOWNSTREAM_TLS_TYPE: &str = "envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext";
const UPSTREAM_TLS_TYPE: &str = "envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext";
const TLS_INSPECTOR_TYPE: &str = "envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector";

/// Envoy default for `per_connection_buffer_limit_bytes`: 1 MiB.
const DEFAULT_CONN_BUFFER_LIMIT: u32 = 1024 * 1024;
/// Envoy default cluster connect timeout: 5s.
const DEFAULT_CONNECT_TIMEOUT: StdDuration = StdDuration::from_secs(5);
/// Envoy default route timeout: 15s (S4).
const DEFAULT_ROUTE_TIMEOUT: StdDuration = StdDuration::from_secs(15);

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

    let mut filter_chains = Vec::new();
    for (i, fc) in l.filter_chains.iter().enumerate() {
        filter_chains.push(convert_filter_chain(
            fc,
            &format!("{path}.filter_chains[{i}]"),
        )?);
    }
    // Envoy rejects two filter chains with byte-identical match criteria at
    // listener creation; catching it here keeps the matcher total (WP-07).
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
    })
}

/// Convert `Listener.listener_filters` (pre-connection filters run against
/// the raw socket before filter-chain matching), plus Envoy's `tls_inspector`
/// auto-injection: if no `tls_inspector` was configured explicitly but a
/// filter chain matches on SNI/ALPN/`transport_protocol: tls`, Envoy inserts
/// a default one so that matching still works — see the doc comment on
/// [`ListenerFilterSpec`] and `docs/envoy-divergences.md`.
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

    if fc.filters.is_empty() {
        return Err(invalid(
            format!("{path}.filters"),
            "filter chain has no filters",
        ));
    }
    if fc.filters.len() > 1 {
        // Both supported filters are terminal; non-terminal L4 filters are WP-09.
        return Err(unsupported(
            format!("{path}.filters[1]"),
            "multiple network filters are not implemented yet (WP-09)",
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
        filters,
    })
}

/// The full 9-criteria `FilterChainMatch` (WP-07). `address_suffix`/`suffix_len`
/// remain unimplemented (Envoy itself marks them `#not-implemented-hide`) and
/// are rejected rather than silently dropped (ground rule #2).
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
    use hcm_v3::http_connection_manager::RouteSpecifier;
    let route_table = match &hcm.route_specifier {
        Some(RouteSpecifier::RouteConfig(rc)) => {
            convert_route_table(rc, &format!("{path}.route_config"))?
        }
        Some(RouteSpecifier::Rds(_)) => {
            return Err(unsupported(
                format!("{path}.rds"),
                "RDS is not implemented yet (WP-21)",
            ))
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
        match type_name(any) {
            ROUTER_TYPE => http_filters.push(HttpFilterSpec::Router),
            _ => {
                return Err(ConfigError::UnknownTypeUrl {
                    field_path: format!("{f_path}.typed_config"),
                    type_url: any.type_url.clone(),
                })
            }
        }
    }
    if http_filters.last() != Some(&HttpFilterSpec::Router) {
        return Err(invalid(
            format!("{path}.http_filters"),
            "the last HTTP filter must be the router (envoy.filters.http.router)",
        ));
    }

    Ok(HttpConnectionManagerConfig {
        stat_prefix: hcm.stat_prefix.clone(),
        route_table: Arc::new(route_table),
        http_filters,
    })
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
    let certificates = convert_downstream_certificates(
        &common.tls_certificates,
        &format!("{common_path}.tls_certificates"),
    )?;
    let validation = convert_validation_context(common, &common_path)?;

    let require_client_certificate = ctx.require_client_certificate.unwrap_or(false);
    if require_client_certificate && validation.is_none() {
        return Err(invalid(
            format!("{cfg_path}.require_client_certificate"),
            "require_client_certificate requires a validation_context",
        ));
    }

    // Rust note: `session_ticket_keys_type` is a proto oneof, so its Rust
    // shape is `Option<enum>` — one variant per oneof member. Only the
    // stateless-resumption bool is supported; the other members are secret
    // material we don't handle yet (WP-22).
    use tls_v3::downstream_tls_context::SessionTicketKeysType;
    let disable_stateless_session_resumption = match &ctx.session_ticket_keys_type {
        None => false,
        Some(SessionTicketKeysType::DisableStatelessSessionResumption(b)) => *b,
        Some(SessionTicketKeysType::SessionTicketKeys(_)) => {
            return Err(unsupported(
                format!("{cfg_path}.session_ticket_keys"),
                "explicit session ticket keys are not implemented yet (WP-22)",
            ))
        }
        Some(SessionTicketKeysType::SessionTicketKeysSdsSecretConfig(_)) => {
            return Err(unsupported(
                format!("{cfg_path}.session_ticket_keys_sds_secret_config"),
                "SDS-delivered session ticket keys are not implemented yet (WP-22)",
            ))
        }
    };

    Ok(DownstreamTlsSpec {
        certificates,
        params,
        alpn_protocols: common.alpn_protocols.clone(),
        validation,
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
/// rustls socket loads the keys (WP-08 chunk B), not here.
fn convert_downstream_certificates(
    certs: &[tls_v3::TlsCertificate],
    path: &str,
) -> Result<Vec<TlsCertificateIR>, ConfigError> {
    if certs.is_empty() {
        return Err(invalid(
            path,
            "at least one tls_certificates entry is required (SDS is not implemented yet — WP-22)",
        ));
    }
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

/// Only the plain (static) `validation_context` oneof member is implemented;
/// the SDS/combined/certificate-provider members are secret-delivery
/// mechanisms that land with WP-22. In strict mode `check_supported_surface`
/// already rejects those members before we get here (they're not in
/// `CommonTlsContext`'s allowed-fields list) — the explicit arms below exist
/// so this function never silently drops one if that surface check is ever
/// relaxed.
fn convert_validation_context(
    common: &tls_v3::CommonTlsContext,
    common_path: &str,
) -> Result<Option<ValidationContextIR>, ConfigError> {
    use tls_v3::common_tls_context::ValidationContextType;
    match &common.validation_context_type {
        None => Ok(None),
        Some(ValidationContextType::ValidationContext(vc)) => Ok(Some(
            convert_validation_context_inner(vc, &format!("{common_path}.validation_context"))?,
        )),
        Some(ValidationContextType::ValidationContextSdsSecretConfig(_)) => Err(unsupported(
            format!("{common_path}.validation_context_sds_secret_config"),
            "SDS-delivered validation contexts are not implemented yet (WP-22)",
        )),
        Some(ValidationContextType::CombinedValidationContext(_)) => Err(unsupported(
            format!("{common_path}.combined_validation_context"),
            "combined (static + SDS) validation contexts are not implemented yet (WP-22)",
        )),
        Some(ValidationContextType::ValidationContextCertificateProvider(_)) => Err(unsupported(
            format!("{common_path}.validation_context_certificate_provider"),
            "certificate-provider validation contexts are not implemented (WP-22)",
        )),
        Some(ValidationContextType::ValidationContextCertificateProviderInstance(_)) => {
            Err(unsupported(
                format!("{common_path}.validation_context_certificate_provider_instance"),
                "certificate-provider validation contexts are not implemented (WP-22)",
            ))
        }
    }
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
/// combining it with `safe_regex` is meaningless, so — per ground rule #2 —
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

// ----------------------------------------------------------------- clusters --

fn convert_cluster(c: &cluster_v3::Cluster, path: &str) -> Result<ClusterConfig, ConfigError> {
    use cluster_v3::cluster::{
        ClusterDiscoveryType, DiscoveryType as ProtoDiscovery, LbPolicy as ProtoLb,
    };

    let discovery = match &c.cluster_discovery_type {
        None => DiscoveryType::Static, // proto default: STATIC
        Some(ClusterDiscoveryType::Type(t)) => match ProtoDiscovery::try_from(*t) {
            Ok(ProtoDiscovery::Static) => DiscoveryType::Static,
            Ok(ProtoDiscovery::StrictDns) => DiscoveryType::StrictDns,
            Ok(ProtoDiscovery::LogicalDns) => DiscoveryType::LogicalDns,
            Ok(ProtoDiscovery::Eds) => {
                return Err(unsupported(
                    format!("{path}.type"),
                    "EDS clusters are not implemented yet (WP-21)",
                ))
            }
            _ => {
                return Err(unsupported(
                    format!("{path}.type"),
                    "this discovery type is not implemented",
                ))
            }
        },
        Some(ClusterDiscoveryType::ClusterType(_)) => {
            return Err(unsupported(
                format!("{path}.cluster_type"),
                "custom cluster types are not implemented",
            ))
        }
    };

    let lb_policy = match ProtoLb::try_from(c.lb_policy) {
        Ok(ProtoLb::RoundRobin) => LbPolicy::RoundRobin,
        Ok(ProtoLb::LeastRequest) => LbPolicy::LeastRequest,
        Ok(ProtoLb::RingHash) => LbPolicy::RingHash,
        Ok(ProtoLb::Random) => LbPolicy::Random,
        Ok(ProtoLb::Maglev) => LbPolicy::Maglev,
        _ => {
            return Err(unsupported(
                format!("{path}.lb_policy"),
                "this LB policy is not implemented",
            ))
        }
    };

    let connect_timeout = match &c.connect_timeout {
        Some(d) => to_std_duration(d, &format!("{path}.connect_timeout"))?,
        None => DEFAULT_CONNECT_TIMEOUT,
    };

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

    Ok(ClusterConfig {
        name: c.name.clone(),
        discovery,
        lb_policy,
        connect_timeout,
        endpoints,
        transport_socket,
        per_connection_buffer_limit_bytes: c
            .per_connection_buffer_limit_bytes
            .unwrap_or(DEFAULT_CONN_BUFFER_LIMIT),
    })
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
    if discovery == DiscoveryType::Static && host.parse::<IpAddr>().is_err() {
        return Err(invalid(
            format!("{path}.endpoint.address.socket_address.address"),
            format!("`{host}` is not an IP address; STATIC clusters require IPs (use STRICT_DNS or LOGICAL_DNS for hostnames)"),
        ));
    }
    Ok(EndpointIR {
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
    let validation = convert_validation_context(common, &common_path)?;

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
            routes.push(convert_route(r, &format!("{vh_path}.routes[{j}]"))?);
        }
        vhosts.push(VirtualHostIR {
            name: vh.name.clone(),
            domains: vh.domains.clone(),
            routes,
        });
    }
    RouteTable::new(rc.name.clone(), vhosts).map_err(|dup| {
        invalid(
            format!("{path}.virtual_hosts"),
            format!("duplicate domain `{}`", dup.0),
        )
    })
}

fn convert_route(r: &route_v3::Route, path: &str) -> Result<RouteEntry, ConfigError> {
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
                .map(|ds| convert_data_source(Some(ds), &format!("{path}.direct_response.body")))
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

    Ok(RouteEntry {
        name: (!r.name.is_empty()).then(|| r.name.clone()),
        matcher,
        action,
        request_headers_to_add,
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

    Ok(ForwardAction {
        target,
        timeout,
        idle_timeout,
        retry_policy,
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
    Ok(RetryPolicyIR {
        retry_on: RetryOn::parse(&rp.retry_on),
        // S3: Envoy default is 1 retry.
        num_retries: rp.num_retries.unwrap_or(1),
        per_try_timeout: rp
            .per_try_timeout
            .as_ref()
            .map(|d| to_std_duration(d, &format!("{path}.per_try_timeout")))
            .transpose()?,
        retriable_status_codes: codes,
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
