//! Lowering: dialect -> Envoy bootstrap resources.
//!
//! Deterministic rules (WP-38):
//! - each provider -> one cluster `provider:<name>` (STATIC for IP hosts,
//!   LOGICAL_DNS for hostnames), upstream TLS + SNI for https, host rewrite
//!   and auth-header injection on the routes that target it;
//! - `routes` -> one listener + HCM + route table; each rule matches the
//!   `x-llmproxy-model` request header via its model glob (exact / prefix /
//!   regex); first match wins, mirroring S1; a 404 direct response backstops
//!   unmatched requests (unless a `*` rule exists);
//! - LLM-safe defaults: total route timeout DISABLED (`0s` — generations are
//!   long); idle_timeout 90s; retries only on connect-failure/reset/refused-
//!   stream/429/5xx-before-first-byte, never after streaming starts (S3).
//!
//! The result is standard Envoy config: it goes through the same strict
//! parse, PGV validation, and IR pipeline as `-c` mode, and `--mode
//! translate` prints it. Dialect features whose runtime lands in a later WP
//! (body-based model extraction, fallbacks, model rewrite, limits, access
//! logs) produce explicit warnings, never silent drops (ground rule #2).

use proxy_config::{ConfigError, ConfigWarning, LoadedBootstrap};
use serde_json::{json, Value};

use crate::model::*;
use crate::parse::parse_host_port;

/// The request header the route table matches models against. Set by clients
/// today; set by the WP-35 model-router filter (from the request body) later.
pub const MODEL_HEADER: &str = "x-llmproxy-model";

const HCM_TYPE_URL: &str = "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager";
const ROUTER_TYPE_URL: &str = "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router";
const UPSTREAM_TLS_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext";
const DOWNSTREAM_TLS_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext";

/// A lowered config: the Envoy bootstrap as JSON plus lowering warnings.
#[derive(Debug)]
pub struct Lowered {
    pub bootstrap: Value,
    pub warnings: Vec<ConfigWarning>,
}

/// Lower and then run the result through the full Envoy-mode pipeline
/// (strict parse + PGV validation), merging warnings.
pub fn lower_to_loaded(config: &SimpleConfig) -> Result<LoadedBootstrap, ConfigError> {
    let lowered = lower(config)?;
    let bytes = serde_json::to_vec(&lowered.bootstrap).map_err(|e| {
        ConfigError::Parse(format!("internal: lowered config not serializable: {e}"))
    })?;
    let mut loaded = proxy_config::parse_bootstrap(
        &bytes,
        proxy_config::ConfigFormat::Json,
        // The lowering must only ever emit fields Envoy mode supports; strict
        // mode here is a self-check, not user-facing leniency.
        proxy_config::StrictMode::Strict,
    )?;
    loaded.warnings.extend(lowered.warnings);
    Ok(loaded)
}

/// Render the lowered bootstrap as YAML (`llm-proxy --mode translate`).
pub fn to_envoy_yaml(config: &SimpleConfig) -> Result<(String, Vec<ConfigWarning>), ConfigError> {
    let lowered = lower(config)?;
    let yaml = serde_yaml::to_string(&lowered.bootstrap)
        .map_err(|e| ConfigError::Parse(format!("internal: cannot render YAML: {e}")))?;
    Ok((yaml, lowered.warnings))
}

pub fn lower(config: &SimpleConfig) -> Result<Lowered, ConfigError> {
    let mut warnings = Vec::new();

    let mut clusters = Vec::new();
    for (name, provider) in &config.providers {
        clusters.push(lower_provider(name, provider, &mut warnings)?);
    }

    let mut routes = Vec::new();
    let mut has_catch_all = false;
    for (i, rule) in config.routes.iter().enumerate() {
        routes.push(lower_route(config, i, rule, &mut warnings)?);
        has_catch_all |= rule.model == "*";
    }
    if !has_catch_all {
        routes.push(json!({
            "match": { "prefix": "/" },
            "direct_response": {
                "status": 404,
                "body": { "inline_string":
                    "{\"error\":{\"message\":\"no route matched the requested model\",\"type\":\"model_not_found\"}}" }
            }
        }));
    }
    if !config.routes.is_empty() {
        warnings.push(warning(
            "routes",
            format!(
                "model routing currently matches the `{MODEL_HEADER}` request header; \
                 body-based model extraction lands with the model-router filter (WP-35)"
            ),
        ));
    }

    let listener = lower_listener(config, routes, &mut warnings)?;

    for (i, _) in config.limits.iter().enumerate() {
        warnings.push(warning(
            format!("limits[{i}]"),
            "limits are recorded but not enforced yet (token limiter WP-34, session limits WP-37)",
        ));
    }
    if config.observability.is_some() {
        warnings.push(warning(
            "observability",
            "access logging is recorded but not emitted yet (WP-24)",
        ));
    }

    let mut bootstrap = json!({
        "static_resources": {
            "listeners": [listener],
            "clusters": clusters,
        }
    });
    if let Some(admin) = &config.admin {
        let (host, port) = parse_host_port(admin, "admin")?;
        bootstrap["admin"] = json!({
            "address": { "socket_address": { "address": host, "port_value": port } }
        });
    }

    Ok(Lowered {
        bootstrap,
        warnings,
    })
}

// ---------------------------------------------------------------- providers --

struct ProviderUpstream {
    host: String,
    port: u16,
    tls: bool,
}

fn provider_upstream(name: &str, provider: &Provider) -> Result<ProviderUpstream, ConfigError> {
    let base_url = provider
        .effective_base_url(name)
        .expect("validated: base_url resolvable");
    let path = format!("providers.{name}.base_url");
    let (tls, rest) = if let Some(rest) = base_url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = base_url.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(ConfigError::InvalidValue {
            field_path: path,
            reason: format!("`{base_url}` must start with http:// or https://"),
        });
    };
    let (authority, url_path) = match rest.split_once('/') {
        Some((a, p)) => (a, p),
        None => (rest, ""),
    };
    if !url_path.is_empty() {
        return Err(ConfigError::InvalidValue {
            field_path: path,
            reason: format!("`{base_url}` has a path prefix; v0 does not support base_url paths"),
        });
    }
    let (host, port) = if authority.contains(':') || authority.starts_with('[') {
        parse_host_port(authority, &path)?
    } else {
        (authority.to_string(), if tls { 443 } else { 80 })
    };
    Ok(ProviderUpstream { host, port, tls })
}

fn lower_provider(
    name: &str,
    provider: &Provider,
    warnings: &mut Vec<ConfigWarning>,
) -> Result<Value, ConfigError> {
    let up = provider_upstream(name, provider)?;
    let cluster_name = format!("provider:{name}");

    // IP endpoints can be STATIC; hostnames resolve via LOGICAL_DNS (one
    // address at a time — the right shape for big API hostnames).
    let discovery = if up.host.parse::<std::net::IpAddr>().is_ok() {
        "STATIC"
    } else {
        "LOGICAL_DNS"
    };
    let connect_timeout = provider
        .connect_timeout
        .unwrap_or(SimpleDuration(std::time::Duration::from_secs(5)));

    let mut cluster = json!({
        "name": cluster_name,
        "type": discovery,
        "connect_timeout": connect_timeout.to_string(),
        "lb_policy": "ROUND_ROBIN",
        "load_assignment": {
            "cluster_name": cluster_name,
            "endpoints": [ { "lb_endpoints": [ { "endpoint": { "address": {
                "socket_address": { "address": up.host, "port_value": up.port }
            } } } ] } ]
        }
    });

    if up.tls {
        let mut tls_config = json!({
            "@type": UPSTREAM_TLS_TYPE_URL,
            "sni": up.host,
        });
        if let Some(ca_file) = &provider.ca_file {
            tls_config["common_tls_context"] = json!({
                "validation_context": { "trusted_ca": { "filename": ca_file } }
            });
        }
        cluster["transport_socket"] = json!({
            "name": "envoy.transport_sockets.tls",
            "typed_config": tls_config,
        });
    } else if provider.ca_file.is_some() {
        warnings.push(warning(
            format!("providers.{name}.ca_file"),
            "ca_file is ignored for plaintext (http://) providers",
        ));
    }

    Ok(cluster)
}

/// The auth header this provider type expects, if a key is configured.
fn auth_header(
    name: &str,
    provider: &Provider,
    warnings: &mut Vec<ConfigWarning>,
) -> Result<Option<(String, String)>, ConfigError> {
    let key = match (&provider.api_key, &provider.api_key_file) {
        (Some(k), None) => k.clone(),
        (None, Some(file)) => {
            warnings.push(warning(
                format!("providers.{name}.api_key_file"),
                "the key file is read once at startup; hot reload lands with WP-35",
            ));
            std::fs::read_to_string(file)
                .map_err(|e| ConfigError::Io {
                    path: file.clone(),
                    reason: e.to_string(),
                })?
                .trim_end()
                .to_string()
        }
        (None, None) => return Ok(None),
        (Some(_), Some(_)) => unreachable!("validated: not both"),
    };
    Ok(Some(match provider.effective_type(name) {
        ProviderType::Anthropic => ("x-api-key".to_string(), key),
        _ => ("authorization".to_string(), format!("Bearer {key}")),
    }))
}

// -------------------------------------------------------------------- routes --

/// Model glob -> Envoy header matcher on [`MODEL_HEADER`]. `*` alone means
/// "match every request" — no header matcher at all.
fn model_glob_matcher(pattern: &str) -> Option<Value> {
    if pattern == "*" {
        return None;
    }
    let string_match = if !pattern.contains('*') {
        json!({ "exact": pattern })
    } else if pattern.ends_with('*') && pattern.matches('*').count() == 1 {
        json!({ "prefix": pattern[..pattern.len() - 1] })
    } else {
        // General glob: escape regex metacharacters, `*` -> `.*`.
        let regex = pattern
            .split('*')
            .map(regex::escape)
            .collect::<Vec<_>>()
            .join(".*");
        json!({ "safe_regex": { "regex": regex } })
    };
    Some(json!({ "name": MODEL_HEADER, "string_match": string_match }))
}

fn lower_route(
    config: &SimpleConfig,
    index: usize,
    rule: &RouteRule,
    warnings: &mut Vec<ConfigWarning>,
) -> Result<Value, ConfigError> {
    let provider_name = &rule.provider.provider;
    let provider = &config.providers[provider_name];
    let up = provider_upstream(provider_name, provider)?;

    if rule.provider.model.is_some() {
        warnings.push(warning(
            format!("routes[{index}].provider"),
            "model rewrite (`provider/model`) needs the request-body rewriter (WP-35); \
             the original model name is forwarded for now",
        ));
    }
    if !rule.fallbacks.is_empty() {
        warnings.push(warning(
            format!("routes[{index}].fallbacks"),
            "fallbacks need the model-router filter (WP-35); \
             only same-provider retries are active for now",
        ));
    }

    let mut r#match = json!({ "prefix": "/" });
    if let Some(header_matcher) = model_glob_matcher(&rule.model) {
        r#match["headers"] = json!([header_matcher]);
    }

    let idle_timeout = rule
        .idle_timeout
        .unwrap_or(SimpleDuration(std::time::Duration::from_secs(90)));
    let mut action = json!({
        "cluster": format!("provider:{provider_name}"),
        // LLM-safe S4 defaults: no total timeout (0 disables), idle-based guard.
        "timeout": "0s",
        "idle_timeout": idle_timeout.to_string(),
        "host_rewrite_literal": up.host,
    });

    // S3, LLM-safe: retry only what is certainly unserved. Envoy's router
    // never retries once response bytes have streamed downstream.
    let attempts = rule.retries.as_ref().map_or(1, |r| r.attempts);
    if attempts > 0 {
        action["retry_policy"] = json!({
            "retry_on": "connect-failure,refused-stream,reset,retriable-status-codes",
            "num_retries": attempts,
            "retriable_status_codes": [429, 500, 502, 503],
        });
    }

    let mut headers_to_add = Vec::new();
    if let Some((key, value)) = auth_header(provider_name, provider, warnings)? {
        headers_to_add.push(json!({
            "header": { "key": key, "value": value },
            "append_action": "OVERWRITE_IF_EXISTS_OR_ADD",
        }));
    }
    for (key, value) in &provider.extra_headers {
        headers_to_add.push(json!({
            "header": { "key": key, "value": value },
            "append_action": "OVERWRITE_IF_EXISTS_OR_ADD",
        }));
    }

    let mut route = json!({ "match": r#match, "route": action });
    if !headers_to_add.is_empty() {
        route["request_headers_to_add"] = Value::Array(headers_to_add);
    }
    Ok(route)
}

// ----------------------------------------------------------------- listener --

fn lower_listener(
    config: &SimpleConfig,
    routes: Vec<Value>,
    _warnings: &mut [ConfigWarning],
) -> Result<Value, ConfigError> {
    let (address, tls) = match &config.listen {
        None => (("0.0.0.0".to_string(), 8080), None),
        Some(Listen::Address(a)) => (parse_host_port(a, "listen")?, None),
        Some(Listen::Full(spec)) => (
            parse_host_port(&spec.address, "listen.address")?,
            spec.tls.as_ref(),
        ),
    };

    let hcm = json!({
        "name": "envoy.filters.network.http_connection_manager",
        "typed_config": {
            "@type": HCM_TYPE_URL,
            "stat_prefix": "llmproxy",
            "route_config": {
                "name": "llmproxy_routes",
                "virtual_hosts": [ {
                    "name": "llmproxy",
                    "domains": ["*"],
                    "routes": routes,
                } ]
            },
            "http_filters": [ {
                "name": "envoy.filters.http.router",
                "typed_config": { "@type": ROUTER_TYPE_URL }
            } ]
        }
    });

    let mut filter_chain = json!({ "filters": [hcm] });
    if let Some(tls) = tls {
        filter_chain["transport_socket"] = json!({
            "name": "envoy.transport_sockets.tls",
            "typed_config": {
                "@type": DOWNSTREAM_TLS_TYPE_URL,
                "common_tls_context": { "tls_certificates": [ {
                    "certificate_chain": { "filename": tls.cert_file },
                    "private_key": { "filename": tls.key_file },
                } ] }
            }
        });
    }

    Ok(json!({
        "name": "llmproxy_listener",
        "address": { "socket_address": {
            "address": address.0, "port_value": address.1
        } },
        "filter_chains": [filter_chain],
    }))
}

fn warning(field_path: impl Into<String>, message: impl Into<String>) -> ConfigWarning {
    ConfigWarning {
        field_path: field_path.into(),
        message: message.into(),
    }
}
