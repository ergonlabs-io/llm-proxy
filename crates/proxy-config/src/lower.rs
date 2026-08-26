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
use proxy_api::envoy::extensions::transport_sockets::tls::v3 as tls_v3;
use proxy_api::envoy::extensions::upstreams::http::v3 as upstream_http_v3;
use proxy_api::envoy::r#type::matcher::v3 as matcher_v3;
use proxy_api::envoy::r#type::v3 as type_v3;
use proxy_observability::access_log::{parse_format, FormatString};
use proxy_observability::ResponseFlag;

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

    // WP-51 increment 3: see `convert_tracing_metadata`'s doc for why this
    // reads `node.metadata` rather than a `static_resources`-adjacent field.
    snapshot.tracing = convert_tracing_metadata(b.node.as_ref(), "node")?;

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
    // WP-35 increment 2b-ii: aggregate members refer to other clusters by
    // name, so they can only be checked once the whole map exists -- this
    // cannot fold into the loop above, because a member may be declared
    // after the aggregate that names it.
    validate_cluster_graph(sr, &snapshot)?;
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
        ],
        // WP-35 increment 2b-i: the only custom cluster type implemented is
        // `envoy.clusters.aggregate` (see `convert_cluster`'s
        // `ClusterDiscoveryType::ClusterType` arm).
        //
        // Both entries are forward-compat insurance, and NO test can exercise
        // either one today -- each message's full field set is already mapped,
        // so there is no real-but-unlisted field a config could set. Do not
        // delete them as dead weight: `allowed_fields` returning `None` skips
        // the field-name check entirely (see `check_supported_surface`), so
        // the day an Envoy proto bump adds a field to either message, its
        // absence here is a silent no-op -- ground rule #1's exact failure
        // mode, arriving with no code change of ours to blame it on.
        "envoy.config.cluster.v3.Cluster.CustomClusterType" => &["name", "typed_config"],
        "envoy.extensions.clusters.aggregate.v3.ClusterConfig" => &["clusters"],
        // WP-50 / WP-47 increment 1: the first proto this project defines
        // itself rather than borrowing from Envoy. Listed for the same
        // forward-compat reason as the two entries above -- every field is
        // mapped today, so no config can trip these -- but with one difference
        // that makes them likelier to matter: WE add the fields to this
        // message. An `llmproxy.filters.v0` field added without a matching
        // entry here would be accepted and ignored, which is ground rule #1's
        // exact failure mode arriving from our own change rather than an Envoy
        // bump.
        "llmproxy.filters.v0.Authentication" => &["hmac_secret", "virtual_keys"],
        "llmproxy.filters.v0.VirtualKey" => &["key_id", "tenant", "digest_hex", "revoked"],
        // Only the `io.llmproxy.provider_auth` namespace under
        // `filter_metadata` is understood -- see
        // `convert_provider_auth_metadata`. `typed_filter_metadata` is not
        // implemented and stays out of this list so setting it is a strict-
        // mode error rather than a silent no-op (ground rule #1); Envoy
        // itself only consults it when the plain map is absent, so no config
        // that already works today needs it.
        "envoy.config.core.v3.Metadata" => &["filter_metadata"],
        // S5 circuit breakers. `per_host_thresholds` is deliberately excluded
        // (we don't model per-host limits); a config setting it is rejected
        // by the surface walk with its dotted path (ground rule #1) rather
        // than silently ignored.
        "envoy.config.cluster.v3.CircuitBreakers" => &["thresholds"],
        // `retry_budget`, `track_remaining`, and `max_connection_pools` are
        // not implemented (no retry-budget engine, no stats publishing, no
        // per-cluster pool cap yet) and stay out of this list on purpose --
        // setting them must fail loudly, not vanish.
        "envoy.config.cluster.v3.CircuitBreakers.Thresholds" => &[
            "priority",
            "max_connections",
            "max_pending_requests",
            "max_requests",
            "max_retries",
        ],
        // S6 active health checking (WP-18). `initial_jitter`,
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
        // S6 passive outlier detection (WP-19). The local-origin split
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
        "envoy.config.endpoint.v3.LbEndpoint" => &["endpoint", "load_balancing_weight"],
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
            "http_filters",
            "generate_request_id",
            "use_remote_address",
            "xff_num_trusted_hops",
            "access_log",
            // WP-51 increment 3: listed so a config setting it gets
            // `convert_hcm`'s specific "not implemented, see the dialect"
            // message instead of the generic surface-check one -- see
            // `HttpConnectionManager.Tracing`'s entry just below for why the
            // rejection happens there rather than mapping anything.
            "tracing",
            // WP-10 S10: the upgrade types this HCM will tunnel. Lowered by
            // `convert_hcm` into `HttpConnectionManagerConfig::upgrade_configs`.
            "upgrade_configs",
        ],
        // WP-10 S10: `filters` is deliberately NOT listed -- per-upgrade
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
        // WP-24: access logging.
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
        ],
        "envoy.config.route.v3.RetryPolicy.RetryBackOff" => &["base_interval", "max_interval"],
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
        // Upstream HTTP protocol selection (S? / WP-13 h2). Only the explicit
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

/// Lower one level of Envoy's `typed_per_filter_config` map (present on
/// `Route`, `VirtualHost`, and `RouteConfiguration`) into IR
/// [`PerFilterConfig`] entries, keyed by filter name. `path` is the dotted
/// path of the owning `typed_per_filter_config` field itself; each entry's
/// error path is `{path}[{name}]`, matching ground rule #1.
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
                        type_url: inner.type_url.clone(),
                        config: Some(config),
                        is_optional: wrapper.is_optional,
                        disabled: false,
                    }
                }
                (false, true) => PerFilterConfig {
                    type_url: String::new(),
                    config: None,
                    is_optional: wrapper.is_optional,
                    disabled: true,
                },
            }
        } else {
            let config = decode_http_filter_config(any, &entry_path)?;
            PerFilterConfig {
                type_url: any.type_url.clone(),
                config: Some(config),
                is_optional: false,
                disabled: false,
            }
        };
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
// WP-24: access logging sinks we implement.
const FILE_ACCESS_LOG_TYPE: &str = "envoy.extensions.access_loggers.file.v3.FileAccessLog";
const STDOUT_ACCESS_LOG_TYPE: &str = "envoy.extensions.access_loggers.stream.v3.StdoutAccessLog";
const STDERR_ACCESS_LOG_TYPE: &str = "envoy.extensions.access_loggers.stream.v3.StderrAccessLog";

/// Envoy default for `per_connection_buffer_limit_bytes`: 1 MiB.
const DEFAULT_CONN_BUFFER_LIMIT: u32 = 1024 * 1024;
/// Envoy default cluster connect timeout: 5s.
const DEFAULT_CONNECT_TIMEOUT: StdDuration = StdDuration::from_secs(5);
/// Envoy default route timeout: 15s (S4).
const DEFAULT_ROUTE_TIMEOUT: StdDuration = StdDuration::from_secs(15);
/// Envoy default `HealthCheck.no_traffic_interval` (S6, WP-18): 60s.
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
    use hcm_v3::http_connection_manager::CodecType as ProtoCodecType;
    use hcm_v3::http_connection_manager::RouteSpecifier;
    // (see `check_lane_h_filter_order` below for the ordering rules these
    // three type URLs participate in)
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
        let is_router = type_name(any) == ROUTER_TYPE;
        // Rust note: the router has no configurable fields (`allowed_fields`
        // maps its type to `&[]`), so its `config` is always `None`; every
        // other filter's `typed_config` is decoded reflectively here — the
        // registry (`proxy-http::FilterRegistry`), not this lowering pass,
        // is what actually understands the bytes (ground rule #2).
        let config = if is_router {
            None
        } else {
            Some(decode_http_filter_config(
                any,
                &format!("{f_path}.typed_config"),
            )?)
        };
        http_filters.push(HttpFilterSpec {
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

    // WP-10: `codec_type` is a plain (non-wrapped) proto3 enum, so its
    // zero-value (0 == AUTO) IS the Envoy default -- no `unwrap_or` needed,
    // unlike the `BoolValue`s just below. `HTTP3` has no IR variant at all
    // (see `CodecType`'s doc): this proxy has no QUIC listener to speak it
    // over, so accepting the value and quietly falling back to `AUTO` would
    // be exactly the silent-drop ground rule #1 forbids -- it must error with
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

    // WP-51 increment 3: `tracing.provider.typed_config` would need to
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
        http_filters,
        codec_type,
        generate_request_id,
        use_remote_address,
        access_logs,
        xff_num_trusted_hops,
        upgrade_configs,
    })
}

/// WP-10 S10: lower an HCM's `upgrade_configs`. `upgrade_type` is required and
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

// --------------------------------------------------- Lane-H filter ordering --

// The Lane-H filter type URLs this pass knows about.
//
// Duplicated as string literals rather than imported from `proxy-filters`,
// which is the crate that actually defines them: `proxy-filters` depends on
// `proxy-config`, so the dependency cannot point this way (ground rule #2).
// The canonical definitions are `proxy_filters::{auth_filter, usage_filter,
// token_limit_filter}::TYPE_URL`; `tests::lane_h_type_urls_match_the_filters`
// in `proxy-filters` pins them equal, so a rename cannot silently disable
// these checks.
// `pub` solely so `tests/lane_h_filter_order.rs` can assert THESE constants
// equal to the filters' own -- pinning a private copy the test re-declares
// would pin nothing.
pub const AUTH_FILTER_TYPE: &str = "type.llmproxy.dev/llmproxy.filters.v0.Authentication";
pub const TOKEN_LIMIT_FILTER_TYPE: &str =
    "type.llmproxy.dev/envoy.config.core.v3.RateLimitSettings";
pub const USAGE_FILTER_TYPE: &str = "type.llmproxy.dev/envoy.config.core.v3.DataSource";

/// Rejects Lane-H filter chains whose order silently disables a filter.
///
/// # Why this is a config error and not a doc comment
///
/// Both orderings below fail *silently* when they are wrong. Nothing errors at
/// runtime, no log line appears, and every request succeeds — the affected
/// filter simply reads `None` out of `StreamInfo` forever and does something
/// plausible-looking with it. That is ground rule #1's failure mode exactly
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
///   WP-50 removed, so the reversed order is a **security** downgrade, not a
///   cosmetic one.
/// - `llmproxy.token_limit` before `llmproxy.usage` — the limiter's *record*
///   is **encode**-side, and reads the usage the usage filter wrote. Because
///   encode order is reversed, "the usage filter has already run" means it is
///   **later** in config order. Reversed, every request records **zero**
///   tokens against its budget: the limit exists and never fires.
///
/// Both rules are stated at their own call sites too
/// (`token_limit_filter`'s module doc); this function is the enforcement.
fn check_lane_h_filter_order(
    http_filters: &[HttpFilterSpec],
    path: &str,
) -> Result<(), ConfigError> {
    // Rust note: `position` returns the index of the FIRST match. A duplicate
    // Lane-H filter is already impossible -- `FilterRegistry` keys on
    // `type_url` -- so first-match is the only match.
    let index_of = |type_url: &str| http_filters.iter().position(|f| f.type_url == type_url);

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
    ];

    for (first_type, first_name, second_type, second_name, reason) in rules {
        // A rule only applies when BOTH filters are present -- either one
        // alone is a perfectly ordinary chain.
        if let (Some(first), Some(second)) = (index_of(first_type), index_of(second_type)) {
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
                // Ground rule #1: the deprecated `format`/`json_format`/
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
/// knows nothing about proto field paths — ground rule #2 keeps that
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
    let (discovery, kind) = match &c.cluster_discovery_type {
        None => (DiscoveryType::Static, ClusterKind::Endpoints), // proto default: STATIC
        Some(ClusterDiscoveryType::Type(t)) => match ProtoDiscovery::try_from(*t) {
            Ok(ProtoDiscovery::Static) => (DiscoveryType::Static, ClusterKind::Endpoints),
            Ok(ProtoDiscovery::StrictDns) => (DiscoveryType::StrictDns, ClusterKind::Endpoints),
            Ok(ProtoDiscovery::LogicalDns) => (DiscoveryType::LogicalDns, ClusterKind::Endpoints),
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
            // `parse_bootstrap` (`validate::validate_message`, WP-04), before
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

    let lb_policy = match ProtoLb::try_from(c.lb_policy) {
        Ok(ProtoLb::RoundRobin) => LbPolicy::RoundRobin,
        Ok(ProtoLb::LeastRequest) => LbPolicy::LeastRequest,
        Ok(ProtoLb::Random) => LbPolicy::Random,
        Ok(ProtoLb::ClusterProvided) => LbPolicy::ClusterProvided,
        // RING_HASH / MAGLEV: the `LbPolicy` variants exist so the IR can
        // model them, but WP-17 deliberately does not implement them yet --
        // a consistent-hash that isn't bit-identical to Envoy's silently
        // breaks session affinity across a mixed fleet, so it needs an Envoy
        // differential harness first. Reject at *config* time rather than at
        // cluster-build time: `proxy-cluster` also refuses to build such a
        // cluster, but that error surfaces after startup, leaving the cluster
        // simply absent and every request to it answered 503 with no
        // explanation. Failing here means `make validate` and startup say
        // exactly what is wrong, with the full dotted path (ground rule #1).
        Ok(policy @ (ProtoLb::RingHash | ProtoLb::Maglev)) => {
            return Err(unsupported(
                format!("{path}.lb_policy"),
                format!(
                    "{} load balancing is not implemented yet (WP-17 follow-up: it requires \
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
    // protocol, and (for the dialect) credentials -- ground rule #1 forbids
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
    // Ground rule #6's third instance (CLAUDE.md): the usage-filter dialect
    // is per-provider, so it rides the same `Cluster.metadata.filter_metadata`
    // smuggling channel as credentials above, under its own namespace.
    let usage_dialect = convert_usage_dialect_metadata(c.metadata.as_ref(), path)?;
    // S6 active health checking (WP-18): meaningful on an aggregate too, in
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
    // S6 passive outlier detection (WP-19): same aggregate reasoning as
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
        usage_dialect,
        health_check,
        outlier_detection,
    })
}

/// WP-35 increment 2b-ii: a cross-cluster post-pass over the assembled
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
/// Ground rule #1's shape exactly: each of these degrades into a silent
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

/// Lower `Cluster.metadata.filter_metadata["io.llmproxy.provider_auth"]`
/// into `ClusterConfig::request_headers_to_add`. The expected shape is
/// `{ headers: [ { key: "...", value: "..." }, ... ] }`; every entry lowers
/// to [`HeaderAppendAction::OverwriteIfExistsOrAdd`], matching what the
/// dialect used to emit at the route level.
///
/// `google.protobuf.Struct` is opaque to the reflective surface walk (it is
/// a well-known type, so `check_supported_surface` stops recursing at its
/// boundary), so ground rule #1's "every field maps or errors" guarantee has
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
        .filter(|k| k.as_str() != "headers")
        .collect();
    unknown.sort();
    if let Some(key) = unknown.first() {
        return Err(unsupported(
            format!("{auth_path}.{key}"),
            format!("`{PROVIDER_AUTH_METADATA_KEY}` only supports a `headers` list"),
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

/// Namespace key the `llmproxy` dialect uses to carry the usage-filter
/// dialect through `Cluster.metadata.filter_metadata` -- ground rule #6's
/// third instance (CLAUDE.md): the dialect is a per-provider property, so it
/// has to follow the cluster that is actually dialled, the same way
/// [`PROVIDER_AUTH_METADATA_KEY`] carries credentials. This increment (WP-35
/// inc 1) only populates [`ClusterConfig::usage_dialect`]; the usage filter
/// itself still reads the route-level `typed_per_filter_config` copy until a
/// later increment plumbs the cluster value through to it.
const USAGE_DIALECT_METADATA_KEY: &str = "io.llmproxy.usage";

/// Lower `Cluster.metadata.filter_metadata["io.llmproxy.usage"]` into
/// [`ClusterConfig::usage_dialect`]. The expected shape is
/// `{ dialect: "openai" | "anthropic" }`.
///
/// Same re-implementation-by-hand rationale as
/// [`convert_provider_auth_metadata`]: `google.protobuf.Struct` is opaque to
/// the reflective surface walk, so ground rule #1 has to be enforced here
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
/// ground rule #1 has to be enforced here directly, and any error names its
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
                "otlp_endpoint" | "service_name" | "sample_ratio"
            )
        })
        .collect();
    unknown.sort();
    if let Some(key) = unknown.first() {
        return Err(unsupported(
            format!("{tracing_path}.{key}"),
            format!(
                "`{TRACING_METADATA_KEY}` only supports `otlp_endpoint`, `service_name`, and \
                 `sample_ratio`"
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

    Ok(Some(TracingConfig {
        otlp_endpoint,
        service_name,
        sample_ratio,
    }))
}

/// Type URL key Envoy expects for the one `typed_extension_protocol_options`
/// entry we implement: HTTP/1-vs-HTTP/2 selection via `explicit_http_config`.
const HTTP_PROTOCOL_OPTIONS_TYPE: &str = "envoy.extensions.upstreams.http.v3.HttpProtocolOptions";

/// Lower a cluster's `typed_extension_protocol_options` map into the IR's
/// single-dimension [`UpstreamProtocol`]. Envoy keys this map by extension
/// name; we only implement the one entry that selects HTTP/1 vs HTTP/2
/// (`envoy.extensions.upstreams.http.v3.HttpProtocolOptions`), so any other
/// key -- or any of that message's fields we don't model -- is rejected with
/// its full dotted path (ground rule #1) rather than silently ignored.
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
/// matches without any error -- exactly ground rule #1's failure mode.
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
    // than accepted-and-ignored (ground rule #1).
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

    let typed_per_filter_config = convert_typed_per_filter_config(
        &r.typed_per_filter_config,
        &format!("{path}.typed_per_filter_config"),
    )?;

    Ok(RouteEntry {
        name: (!r.name.is_empty()).then(|| r.name.clone()),
        matcher,
        action,
        request_headers_to_add,
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

    // Ground rule #1. The router re-runs host selection once per retry, which
    // *is* the Envoy default (1) -- but it has no notion of "avoid a host this
    // request already tried", so any explicit value above 1 would parse,
    // validate, and then do nothing. Refuse it instead of accepting a knob we
    // silently drop.
    if host_selection_retry_max_attempts > 1 {
        return Err(unsupported(
            format!("{path}.host_selection_retry_max_attempts"),
            "values above 1 are not implemented yet (WP-14 follow-up: the router re-runs host \
             selection per retry but cannot yet exclude already-tried hosts, so a higher \
             attempt count would have no effect)",
        ));
    }

    let retry_on = RetryOn::parse(&rp.retry_on);

    // Ground rule #1. `envoy-ratelimited` retries when the response carries
    // `x-envoy-ratelimited`, a header only a rate-limit filter sets -- and no
    // such filter exists yet (WP-31/WP-32), so nothing can ever produce the
    // condition. Accepting the token would mean a config that reads as "retry
    // rate-limited responses" and never retries anything.
    if retry_on.envoy_ratelimited {
        return Err(unsupported(
            format!("{path}.retry_on"),
            "the `envoy-ratelimited` retry trigger is not implemented yet (it fires on the \
             `x-envoy-ratelimited` response header, which no filter sets until WP-31/WP-32 \
             land the rate-limit filters)",
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
        retriable_status_codes: codes,
        retry_back_off,
        host_selection_retry_max_attempts,
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
