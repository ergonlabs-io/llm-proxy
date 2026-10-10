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
//! (fallbacks, model rewrite, limits, access logs) produce explicit
//! warnings, never silent drops (ground rule #2).

use std::collections::HashMap;

use proxy_config::{ConfigError, ConfigWarning, LoadedBootstrap};
use serde_json::{json, Value};

use crate::model::*;
use crate::parse::parse_host_port;

/// The request header the route table matches models against. Populated
/// from the request BODY by the body-rewrite filter (WP-45's consumer B,
/// `proxy_filters::body_rewrite_filter`) before routing runs -- overwriting
/// or removing any client-supplied value, never trusting it (see that
/// filter's module doc). `needs_body_rewrite_filter` below is what actually
/// guarantees the filter is in the chain whenever this header is matched
/// against.
pub const MODEL_HEADER: &str = "x-llmproxy-model";

const HCM_TYPE_URL: &str = "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager";
const ROUTER_TYPE_URL: &str = "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router";

/// The auth filter's name in `http_filters` -- always the FIRST entry when
/// `auth:` is configured (see [`lower_listener`]): ahead of
/// `llmproxy.body_rewrite` so an unauthenticated request is refused before
/// the body-peek filter buffers anything, and ahead of `llmproxy.token_limit`
/// so the limiter buckets on the tenant this filter resolves --
/// `proxy_config::lower::check_lane_h_filter_order` enforces the second half
/// of that ordering as a hard error, so getting it wrong fails loudly rather
/// than silently. No per-route override exists for this filter, so unlike
/// [`USAGE_FILTER_NAME`]/[`BODY_REWRITE_FILTER_NAME`] this name never appears
/// in a route's `typed_per_filter_config`.
const AUTH_FILTER_NAME: &str = "llmproxy.auth";

/// Must equal `proxy_filters::auth_filter::TYPE_URL`. Duplicated for the same
/// dependency-tree reason as [`USAGE_FILTER_TYPE_URL`]; `tests/auth.rs`'s
/// `auth_filter_type_url_matches_the_filter` pins the two together.
const AUTH_FILTER_TYPE_URL: &str = "type.llmproxy.dev/llmproxy.filters.v0.Authentication";

/// The usage/token filter's name in `http_filters`. This exact string is also
/// the key every route's `typed_per_filter_config` override is matched
/// against — if the two ever drift apart the config fails to load, because an
/// override naming a filter absent from the chain is a hard error.
const USAGE_FILTER_NAME: &str = "llmproxy.usage";

/// Must equal `proxy_filters::usage_filter::TYPE_URL`. Duplicated rather than
/// imported: this is a config crate, and depending on `proxy-filters` would
/// drag the whole data plane (and `proxy-http`) into the dependency tree of
/// something that only ever emits JSON — the same reason `ROUTER_TYPE_URL`
/// above is a literal. `dialect.rs`'s `usage_filter_type_url_matches_the_filter`
/// pins the two together via a dev-dependency, and a drift that slipped past
/// it would still be a loud bind-time error ("no registered factory for
/// type_url"), never a silent skip.
const USAGE_FILTER_TYPE_URL: &str = "type.llmproxy.dev/llmproxy.filters.v0.Usage";

/// The body-rewrite filter's name in `http_filters`, gated by
/// `observability.force_usage_reporting` (default `true`). Same
/// name/override-key contract as [`USAGE_FILTER_NAME`].
const BODY_REWRITE_FILTER_NAME: &str = "llmproxy.body_rewrite";

/// Must equal `proxy_filters::body_rewrite_filter::TYPE_URL`. Duplicated for
/// the same dependency-tree reason as [`USAGE_FILTER_TYPE_URL`];
/// `dialect.rs`'s `body_rewrite_filter_type_url_matches_the_filter` pins it.
const BODY_REWRITE_FILTER_TYPE_URL: &str = "type.llmproxy.dev/llmproxy.filters.v0.BodyRewrite";
/// The token-limit filter's name in `http_filters`, emitted only when a
/// `limits` entry actually lowers (see [`lower_limits`]). No per-route
/// override exists for this filter (its module doc: "no per-route config in
/// this increment"), so unlike [`USAGE_FILTER_NAME`] / [`BODY_REWRITE_FILTER_NAME`]
/// this name never appears in a route's `typed_per_filter_config`.
const TOKEN_LIMIT_FILTER_NAME: &str = "llmproxy.token_limit";

/// Must equal `proxy_filters::token_limit_filter::TYPE_URL`. Duplicated for
/// the same dependency-tree reason as [`USAGE_FILTER_TYPE_URL`];
/// `dialect.rs`'s IR-survival test pins the two together the same way.
const TOKEN_LIMIT_FILTER_TYPE_URL: &str = "type.llmproxy.dev/llmproxy.filters.v0.TokenLimit";

/// The only `LimitKey` the thin-slice token limiter enforces: its bucket key
/// is hardcoded to the `authorization` header (see `token_limit_filter`'s
/// module doc, "Config" section).
const ENFORCED_LIMIT_HEADER: &str = "authorization";

/// The `typed_extension_protocol_options` map key, and (prefixed with
/// `type.googleapis.com/`) its `@type` -- must match
/// `proxy_config::lower::HTTP_PROTOCOL_OPTIONS_TYPE` exactly, for the same
/// dependency-tree reason as `USAGE_FILTER_TYPE_URL` above (this crate never
/// links `proxy-config`'s proto types, only its JSON surface).
const HTTP_PROTOCOL_OPTIONS_KEY: &str = "envoy.extensions.upstreams.http.v3.HttpProtocolOptions";
const HTTP_PROTOCOL_OPTIONS_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions";

const UPSTREAM_TLS_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext";
const DOWNSTREAM_TLS_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext";
const STDOUT_ACCESS_LOG_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog";
const STDERR_ACCESS_LOG_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StderrAccessLog";
const FILE_ACCESS_LOG_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog";

/// The dialect's default text access-log line: Envoy's own default
/// (`proxy_config::ir::DEFAULT_ACCESS_LOG_FORMAT`) trimmed of the fields that
/// don't earn their width here (upstream service time, X-Forwarded-For,
/// User-Agent), plus the LLM token and streaming-latency operators — token
/// accounting is the product this proxy exists for, so the dialect's default
/// line carries it.
///
/// `%LLM_TPOT%` is here, not just `%LLM_TTFT%`, and that is the point of the
/// pair: TTFT says how long the user waited to see *anything*, TPOT says how
/// fast it then streamed. Either alone hides the failure the other catches.
/// (Added 2026-08-08: WP-46 built `%LLM_TPOT%`, `%LLM_MAX_STALL%` and
/// `%LLM_RESPONSE_CHUNKS%`, but no dialect format ever emitted them — so a
/// user configuring this proxy through its own dialect could not get TPOT at
/// any setting, which the v0.1.0 gate requires.)
const ACCESS_LOG_TEXT_FORMAT: &str = concat!(
    "[%START_TIME%] \"%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)% %PROTOCOL%\" ",
    "%RESPONSE_CODE% %RESPONSE_FLAGS% %BYTES_RECEIVED% %BYTES_SENT% %DURATION% ",
    "\"%REQ(X-REQUEST-ID)%\" \"%UPSTREAM_HOST%\" ",
    "llm_tokens=\"%LLM_INPUT_TOKENS%/%LLM_CACHED_TOKENS%/%LLM_CACHE_CREATION_TOKENS%/",
    "%LLM_OUTPUT_TOKENS%/%LLM_TOTAL_TOKENS%\" llm_ttft_ms=\"%LLM_TTFT%\" ",
    "llm_tpot_ms=\"%LLM_TPOT%\" llm_max_stall_ms=\"%LLM_MAX_STALL%\" ",
    "llm_response_chunks=\"%LLM_RESPONSE_CHUNKS%\" ",
    "key_id=\"%LLM_KEY_ID%\" tenant=\"%LLM_TENANT%\" user_id=\"%LLM_USER_ID%\" ",
    "requested_model=\"%LLM_REQUESTED_MODEL%\" selected_provider=\"%UPSTREAM_CLUSTER%\" ",
    "selected_model=\"%LLM_SELECTED_MODEL%\" rate_card_version=\"%LLM_RATE_CARD_VERSION%\" ",
    "llm_list_cost_nanodollars=\"%LLM_LIST_COST%\"\n",
);

/// The header Anthropic requires on every Messages API request.
const ANTHROPIC_VERSION_HEADER: &str = "anthropic-version";

/// The API version the dialect pins when the user doesn't choose one.
/// Anthropic versions its API by date and treats this header as mandatory;
/// `2023-06-01` is the long-standing stable version. Bumping it is a
/// deliberate compatibility decision, not a routine dependency update —
/// a newer version can change response shapes that `proxy-filters`' usage
/// extraction depends on.
const DEFAULT_ANTHROPIC_VERSION: &str = "2023-06-01";

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
        clusters.push(lower_provider(config, name, provider, &mut warnings)?);
    }

    let mut routes = Vec::new();
    let mut has_catch_all = false;
    for (i, rule) in config.routes.iter().enumerate() {
        let (route, aggregate_cluster) = lower_route(config, i, rule, &mut warnings)?;
        routes.push(route);
        // WP-35 increment 2c: a route with `fallbacks` lowers an extra
        // `envoy.clusters.aggregate` cluster alongside its provider
        // clusters -- declaration order doesn't matter (Envoy resolves the
        // member graph after every cluster is assembled; see
        // `aggregate_declared_before_its_members_still_lowers` in
        // `proxy-config`), so appending here is fine even though the
        // provider clusters above were built first.
        if let Some(aggregate_cluster) = aggregate_cluster {
            clusters.push(aggregate_cluster);
        }
        has_catch_all |= rule.model == "*";
    }
    // `models:` entries (WP-49) each get an implicit route on their own
    // name, evaluated after the explicit `routes:` list (first match wins,
    // same S1 rule) and before the 404 backstop. WP-49 increment 2:
    // `model_catalog_order` puts them in exact > longest-prefix > `*`
    // precedence order rather than the catalogue's alphabetical key order.
    for (name, model) in model_catalog_order(config) {
        let (route, aggregate_cluster) = lower_model(config, name, model)?;
        routes.push(route);
        if let Some(aggregate_cluster) = aggregate_cluster {
            clusters.push(aggregate_cluster);
        }
    }
    // A bare `*` catalogue entry (increment 2's empty-prefix tier) is just
    // as much a catch-all as a `routes:` rule with `model: "*"` -- it also
    // needs to suppress the synthetic 404 below, or that 404 becomes a dead,
    // never-reached route sitting after it (harmless, but confusing output).
    has_catch_all |= config.models.contains_key("*");
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
    // A configured model catalog is served locally from the same immutable
    // snapshot as routing. Wildcard patterns are routing rules, not model IDs.
    if !config.models.is_empty() {
        let data: Vec<Value> = config.models.keys()
            .filter(|name| !name.contains('*'))
            .map(|name| json!({ "id": name, "object": "model", "created": 0, "owned_by": "llm-proxy" }))
            .collect();
        let body = json!({ "object": "list", "data": data }).to_string();
        let catalog_route = json!({
            "name": "llmproxy_model_catalog",
            "match": { "path": "/v1/models" },
            "direct_response": { "status": 200, "body": { "inline_string": body } },
        });
        let index = routes
            .iter()
            .position(|route| {
                route["match"]["prefix"] == "/" && route["match"]["headers"].is_null()
            })
            .unwrap_or(routes.len());
        routes.insert(index, catalog_route);
    }

    // WP-45: the body-rewrite filter (inserted below by
    // `needs_body_rewrite_filter`) now scans the request body and publishes
    // `MODEL_HEADER` from it before routing runs, so `routes`/`models`
    // matching that header is body-derived, not merely a header the client
    // happens to set -- no warning needed here anymore.

    let auth_filter = lower_auth(config, &mut warnings)?;
    let token_limit_filter = lower_limits(config, &mut warnings)?;
    let pricing = lower_pricing(config, &mut warnings)?;

    let access_log = config
        .observability
        .as_ref()
        .and_then(|o| o.access_logs.as_ref())
        .map(lower_access_log);
    let listener = lower_listener(
        config,
        routes,
        access_log,
        auth_filter,
        token_limit_filter,
        pricing,
        &mut warnings,
    )?;

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
    // Both namespace keys share one `node.metadata` object rather than each
    // replacing it. Written as a merge (read-modify-write) rather than two
    // assignments because the two blocks are independently optional: a config
    // with only `observability.metrics` and one with both must both lower to a
    // valid `node`, and an unconditional second assignment would silently
    // clobber whichever block was written first.
    let mut metadata = serde_json::Map::new();
    if let Some(tracing) = config
        .observability
        .as_ref()
        .and_then(|o| o.tracing.as_ref())
    {
        metadata.insert(TRACING_METADATA_KEY.to_string(), lower_tracing(tracing)?);
    }
    if let Some(metrics) = config
        .observability
        .as_ref()
        .and_then(|o| o.metrics.as_ref())
    {
        metadata.insert(METRICS_METADATA_KEY.to_string(), lower_metrics(metrics)?);
    }
    if !metadata.is_empty() {
        bootstrap["node"] = json!({ "metadata": metadata });
    }

    Ok(Lowered {
        bootstrap,
        warnings,
    })
}

// -------------------------------------------------------------- pricing --

/// Validate the rate-card input at dialect load. It is intentionally separate
/// from the pricing library: this frontend must not pull the data plane into
/// `--mode translate`, and errors must name operator-facing dotted paths.
fn lower_pricing(
    config: &SimpleConfig,
    warnings: &mut Vec<ConfigWarning>,
) -> Result<Option<Value>, ConfigError> {
    let Some(pricing) = config.pricing.as_ref() else {
        return Ok(None);
    };
    match (&pricing.price_list_file, &pricing.price_list) {
        (Some(file), None) => {
            warnings.push(warning(
                "pricing.price_list_file",
                "the price list is read once at startup; update it with a config reload",
            ));
            let contents = std::fs::read_to_string(file).map_err(|e| ConfigError::Io {
                path: file.clone(),
                reason: e.to_string(),
            })?;
            let de = serde_yaml::Deserializer::from_str(&contents);
            let list: PriceListDef = serde_path_to_error::deserialize(de).map_err(|error| {
                ConfigError::InvalidValue {
                    field_path: pricing_file_path(&error.path().to_string()),
                    reason: error.inner().to_string(),
                }
            })?;
            validate_price_list(&list)?;
            Ok(Some(price_list_filter_config(config, &list)))
        }
        (None, Some(list)) => {
            validate_price_list(list)?;
            Ok(Some(price_list_filter_config(config, list)))
        }
        (None, None) => Err(ConfigError::InvalidValue {
            field_path: "pricing".into(),
            reason: "set exactly one of price_list_file or price_list".into(),
        }),
        (Some(_), Some(_)) => Err(ConfigError::InvalidValue {
            field_path: "pricing".into(),
            reason: "set exactly one of price_list_file or price_list, not both".into(),
        }),
    }
}

/// Serialize the strict dialect card into the usage filter's pricing JSON
/// carrier. This is listener-level (not route-level): the card
/// must be captured once per stream, while the actual provider is resolved
/// from the cluster the router really dialled at response end.
fn price_list_filter_config(config: &SimpleConfig, list: &PriceListDef) -> Value {
    let entries: Vec<Value> = list
        .entries
        .iter()
        .map(|entry| {
            json!({
                "cached_input_unpriced": entry.cached_input_unpriced,
                "cache_write_unpriced": entry.cache_write_unpriced,
                "provider_type": entry.provider_type,
                "model": entry.model,
                "tier_mode": match entry.tier_mode.expect("validated") {
                    TierModeDef::WholeRequest => "whole_request",
                    TierModeDef::Graduated => "graduated",
                },
                "tiers": entry.tiers.iter().map(|tier| json!({
                    "up_to": tier.up_to,
                    "input_nanodollars_per_token": tier.input_nanodollars_per_token,
                    "cached_input_nanodollars_per_token": tier.cached_input_nanodollars_per_token,
                    "cache_write_nanodollars_per_token": tier.cache_write_nanodollars_per_token,
                    "output_nanodollars_per_token": tier.output_nanodollars_per_token,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    let providers: serde_json::Map<String, Value> = config
        .providers
        .iter()
        .map(|(name, provider)| {
            (
                format!("provider:{name}"),
                Value::String(provider.effective_type(name).as_str().to_string()),
            )
        })
        .collect();
    json!({
        "catalog": config.pricing.as_ref().and_then(|pricing| pricing.catalog.as_ref()),
        "price_list": {
            "version": list.version,
            "effective_from": list.effective_from,
            "entries": entries,
        },
        "providers": providers,
    })
}

fn pricing_file_path(path: &str) -> String {
    if path.is_empty() || path == "." {
        "pricing.price_list".into()
    } else {
        format!("pricing.price_list.{path}")
    }
}

fn validate_price_list(list: &PriceListDef) -> Result<(), ConfigError> {
    chrono::DateTime::parse_from_rfc3339(&list.effective_from).map_err(|error| {
        ConfigError::InvalidValue {
            field_path: "pricing.price_list.effective_from".into(),
            reason: format!("must be RFC3339: {error}"),
        }
    })?;
    if list.entries.is_empty() {
        return Err(ConfigError::InvalidValue {
            field_path: "pricing.price_list.entries".into(),
            reason: "at least one entry is required".into(),
        });
    }
    let mut seen = HashMap::new();
    for (entry_index, entry) in list.entries.iter().enumerate() {
        let path = format!("pricing.price_list.entries[{entry_index}]");
        if entry.provider_type.is_empty() {
            return Err(ConfigError::InvalidValue {
                field_path: format!("{path}.provider_type"),
                reason: "must not be empty".into(),
            });
        }
        if entry.model.is_empty() {
            return Err(ConfigError::InvalidValue {
                field_path: format!("{path}.model"),
                reason: "must not be empty".into(),
            });
        }
        if let Some(first) = seen.insert((&entry.provider_type, &entry.model), entry_index) {
            return Err(ConfigError::InvalidValue {
                field_path: format!("{path}.model"),
                reason: format!("duplicate (provider_type, model), first used at entries[{first}]"),
            });
        }
        if entry.tier_mode.is_none() {
            return Err(ConfigError::InvalidValue {
                field_path: format!("{path}.tier_mode"),
                reason: "required; whole_request and graduated have different money semantics"
                    .into(),
            });
        }
        if entry.tiers.is_empty() {
            return Err(ConfigError::InvalidValue {
                field_path: format!("{path}.tiers"),
                reason: "at least one tier is required".into(),
            });
        }
        let mut previous = None;
        let mut open_ended = 0;
        for (tier_index, tier) in entry.tiers.iter().enumerate() {
            if let Some(up_to) = tier.up_to {
                if previous.is_some_and(|previous| up_to <= previous) {
                    return Err(ConfigError::InvalidValue {
                        field_path: format!("{path}.tiers[{tier_index}].up_to"),
                        reason: "must strictly increase".into(),
                    });
                }
                previous = Some(up_to);
            } else {
                open_ended += 1;
            }
        }
        if open_ended != 1 {
            return Err(ConfigError::InvalidValue {
                field_path: format!("{path}.tiers"),
                reason: "exactly one open-ended tier is required".into(),
            });
        }
        if entry.tiers.last().is_some_and(|tier| tier.up_to.is_some()) {
            return Err(ConfigError::InvalidValue {
                field_path: format!("{path}.tiers[{}].up_to", entry.tiers.len() - 1),
                reason: "the open-ended tier must be last".into(),
            });
        }
    }
    Ok(())
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
    config: &SimpleConfig,
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
        // Rust note: `trusted_ca` and `system_root_certs` are mutually
        // exclusive in `CertificateValidationContext` (proxy-config's
        // lowering rejects both being set), so this `if`/`else` can only
        // ever populate one of them.
        //
        // An `UpstreamTlsContext` with no validation context at all is
        // Envoy's documented (and dangerous) default: it disables server
        // certificate verification entirely. That parity is intentional
        // for the raw Envoy-mode surface, but this dialect is our own
        // opinionated one, so a provider with no explicit `ca_file` still
        // gets verified against the platform trust store instead of
        // silently accepting any certificate.
        //
        // Neither `trusted_ca` nor `system_root_certs` alone checks the
        // upstream's *identity* -- Envoy's `CertificateValidationContext`
        // validates chain trust only; a `match_typed_subject_alt_names`
        // entry is the actual hostname check (see
        // `proxy-core/tests/upstream_tls.rs` for the runtime proof). Chain
        // trust without identity is not authentication: without this, any
        // cert signed by any public CA for any domain would be accepted
        // for `up.host`, which is exactly the MITM TLS is meant to
        // prevent. Envoy-mode must stay permissive by default (that's
        // genuine upstream parity for users porting real Envoy configs),
        // but the dialect is our own opinionated surface, so it can afford
        // to be strict here.
        let mut validation_context = if let Some(ca_file) = &provider.ca_file {
            json!({ "trusted_ca": { "filename": ca_file } })
        } else {
            json!({ "system_root_certs": {} })
        };
        validation_context["match_typed_subject_alt_names"] = json!([
            { "san_type": "DNS", "matcher": { "exact": up.host } }
        ]);
        let tls_config = json!({
            "@type": UPSTREAM_TLS_TYPE_URL,
            "sni": up.host,
            "common_tls_context": { "validation_context": validation_context },
        });
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

    // `protocol: http2` is the on-ramp to `proxy-http::upstream_pool`'s h2
    // upstream connection cache (WP-15 slice A) -- see this cluster's own
    // `UpstreamProtocol` doc. `http1` (the default, `None` here) emits
    // NOTHING: `proxy_config::lower::convert_upstream_protocol` already reads
    // an empty/absent `typed_extension_protocol_options` map as `Http1`
    // (Envoy's own default for an unconfigured cluster), so emitting an
    // explicit `http_protocol_options: {}` block would be redundant JSON that
    // changes the emitted bytes for every config predating this field without
    // changing behavior -- omitting it keeps that byte-identical guarantee.
    //
    // This sits on the PROVIDER cluster, which is exactly right per ground
    // rule #6: `lower_provider` runs once per `providers` entry and never
    // touches the `fallback:route-{index}` aggregate cluster `lower_route`
    // builds separately, so a route with fallbacks still lowers cleanly --
    // `typed_extension_protocol_options` on an aggregate is a hard load
    // error (see the comment on `aggregate` below).
    if provider.protocol == Some(UpstreamProtocol::Http2) {
        cluster["typed_extension_protocol_options"] = json!({
            HTTP_PROTOCOL_OPTIONS_KEY: {
                "@type": HTTP_PROTOCOL_OPTIONS_TYPE_URL,
                "explicit_http_config": { "http2_protocol_options": {} }
            }
        });
    }

    // Provider credentials live on the CLUSTER, not the route -- see
    // `ClusterConfig::request_headers_to_add`'s doc comment in
    // `proxy-config/src/ir.rs`. There is no Envoy `Cluster` field for
    // per-provider auth headers, so this dialect smuggles them through
    // `metadata.filter_metadata["io.llmproxy.provider_auth"]`, which
    // `proxy-config::lower::convert_provider_auth_metadata` reads back out
    // on the way through the identical strict-parse -> PGV -> IR pipeline
    // every Envoy-mode config also goes through ("one engine, two
    // front-ends" -- this module's own doc comment). This runs once per
    // provider (this function is called once per `providers` entry), so a
    // provider used by five routes/models still gets exactly one set of
    // warnings, not five identical copies.
    let mut headers_to_add = provider_headers_to_add(name, provider, warnings)?;
    // WP-35 increment 2c: the Host header follows the CLUSTER, not the
    // route. A route with fallbacks can fail over to a different provider
    // cluster (see `lower_route`'s aggregate-cluster handling), and
    // `host_rewrite_literal` on the ROUTE would still carry the PRIMARY
    // provider's host to whichever member actually serves the request --
    // the exact "value pinned to the routing decision instead of the
    // connection" bug class WP-35 increment 1a existed to kill. Setting it
    // here too means the member that actually dials the request always
    // supplies its own Host, exactly like its credentials
    // (`router.rs`'s `apply_header_mutations` call applies cluster-level
    // `request_headers_to_add` after the route-level transforms and lets it
    // win on a key collision). This runs for every provider, not only ones
    // used in a fallback chain: a route with no fallbacks already sets the
    // identical value via `host_rewrite_literal`, so this is a no-op there,
    // and one rule is simpler than two.
    headers_to_add.push(json!({ "key": "host", "value": up.host }));
    // WP-35 increment 1 (ground rule #6's third instance, AGENTS.md invariant 6): the
    // usage-filter dialect is per-provider too, so it rides onto the CLUSTER
    // alongside credentials and `Host` above rather than staying only on the
    // route's `typed_per_filter_config` -- that route-level copy is left
    // completely unchanged by this increment (both carriers must agree; see
    // `dialect.rs`'s test for that), and the usage filter itself does not
    // read this one yet. This runs once per provider, exactly like the
    // credential/Host headers above, so a provider used by five routes still
    // gets exactly one copy.
    let dialect = cluster_usage_dialect(config, name, provider)?;
    let provider_type = provider.effective_type(name);
    let mut provider_auth = json!({
        "headers": headers_to_add,
        "models": provider_model_rewrites(config, name),
    });
    let mut path_template = None;
    match provider_type {
        ProviderType::Vertex => {
            let access_token = provider_secret(
                name,
                "access_token",
                provider.access_token.as_ref(),
                provider.access_token_file.as_ref(),
                warnings,
            )?;
            provider_auth["scheme"] = json!("vertex-oauth2");
            provider_auth["access_token"] = json!(access_token);
            path_template = Some(json!({
                "scheme": "vertex",
                "project": provider.project.as_deref().expect("validated: Vertex project"),
                "location": provider.location.as_deref().expect("validated: Vertex location"),
                "publisher": provider.publisher.as_deref().expect("validated: Vertex publisher"),
                "models": provider_model_rewrites(config, name),
            }));
        }
        ProviderType::Bedrock => {
            let access_key_id = provider_secret(
                name,
                "access_key_id",
                provider.access_key_id.as_ref(),
                provider.access_key_id_file.as_ref(),
                warnings,
            )?;
            let secret_access_key = provider_secret(
                name,
                "secret_access_key",
                provider.secret_access_key.as_ref(),
                provider.secret_access_key_file.as_ref(),
                warnings,
            )?;
            let session_token = match (
                provider.session_token.as_ref(),
                provider.session_token_file.as_ref(),
            ) {
                (None, None) => None,
                (inline, file) => Some(provider_secret(
                    name,
                    "session_token",
                    inline,
                    file,
                    warnings,
                )?),
            };
            provider_auth["scheme"] = json!("bedrock-sigv4");
            provider_auth["region"] = json!(provider
                .region
                .as_deref()
                .expect("validated: Bedrock region"));
            provider_auth["access_key_id"] = json!(access_key_id);
            provider_auth["secret_access_key"] = json!(secret_access_key);
            if let Some(token) = session_token {
                provider_auth["session_token"] = json!(token);
            }
            path_template = Some(json!({
                "scheme": "bedrock",
                "models": provider_model_rewrites(config, name),
            }));
        }
        _ => {}
    }
    cluster["metadata"] = json!({
        "filter_metadata": {
            PROVIDER_AUTH_METADATA_KEY: provider_auth,
            USAGE_DIALECT_METADATA_KEY: { "dialect": dialect },
        }
    });
    if let Some(template) = path_template {
        cluster["metadata"]["filter_metadata"][PATH_TEMPLATE_METADATA_KEY] = template;
    }

    if provider.effective_type(name) == ProviderType::Openrouter {
        cluster["metadata"]["filter_metadata"][PATH_REWRITE_METADATA_KEY] = json!({
            "match_prefix": "/v1",
            "replacement_prefix": "/api/v1",
        });
    }

    if provider.effective_type(name) == ProviderType::AzureOpenai {
        let deployment = provider
            .deployment
            .as_deref()
            .expect("validated: Azure deployment is present");
        let api_version = provider
            .api_version
            .as_deref()
            .expect("validated: Azure api_version is present");
        cluster["metadata"]["filter_metadata"][PATH_REWRITE_METADATA_KEY] = json!({
            "match_prefix": "/v1",
            "replacement_prefix": format!("/openai/deployments/{deployment}"),
            "query": format!("api-version={api_version}"),
        });
    }

    Ok(cluster)
}

/// Read one provider secret during config compilation. Runtime requests only
/// see the immutable value carried by the published cluster snapshot.
fn provider_secret(
    provider_name: &str,
    field: &str,
    inline: Option<&String>,
    file: Option<&String>,
    warnings: &mut Vec<ConfigWarning>,
) -> Result<String, ConfigError> {
    let value = match (inline, file) {
        (Some(value), None) => value.clone(),
        (None, Some(file)) => {
            warnings.push(warning(
                format!("providers.{provider_name}.{field}_file"),
                "the credential file is read once at startup; hot reload is required for rotation",
            ));
            std::fs::read_to_string(file)
                .map_err(|e| ConfigError::Io {
                    path: file.clone(),
                    reason: e.to_string(),
                })?
                .trim_end()
                .to_string()
        }
        (None, None) => {
            return Err(ConfigError::InvalidValue {
                field_path: format!("providers.{provider_name}.{field}"),
                reason: "is required".to_string(),
            });
        }
        (Some(_), Some(_)) => unreachable!("validated: provider secret sources are exclusive"),
    };
    if value.is_empty() {
        return Err(ConfigError::InvalidValue {
            field_path: format!("providers.{provider_name}.{field}"),
            reason: "must not be empty".to_string(),
        });
    }
    Ok(value)
}

fn provider_model_rewrites(config: &SimpleConfig, provider_name: &str) -> Vec<Value> {
    model_catalog_order(config)
        .into_iter()
        .filter_map(|(pattern, model)| {
            model.providers.iter().find_map(|entry| {
                if entry.provider() != provider_name {
                    return None;
                }
                entry.model().map(|upstream_model| {
                    json!({
                        "pattern": pattern,
                        "upstream_model": upstream_model,
                    })
                })
            })
        })
        .collect()
}

/// Namespace key under `Cluster.metadata.filter_metadata` this dialect uses
/// to carry provider credentials -- must match
/// `proxy_config::lower::PROVIDER_AUTH_METADATA_KEY` exactly, since the two
/// crates only agree on this string by convention (protos never cross the
/// `proxy-config`/`proxy-xds` boundary, so there is no shared Rust type to
/// pin it). `dialect.rs` tests assert this key by its literal value for the
/// same reason `USAGE_FILTER_TYPE_URL` above is pinned by a dev-dependency
/// test rather than trusted to stay in sync.
const PROVIDER_AUTH_METADATA_KEY: &str = "io.llmproxy.provider_auth";

/// Namespace key for provider-owned path/query rewrites.
const PATH_REWRITE_METADATA_KEY: &str = "io.llmproxy.path_rewrite";

/// Namespace key for provider-specific model URL templates.
const PATH_TEMPLATE_METADATA_KEY: &str = "io.llmproxy.path_template";

/// Namespace key under `Cluster.metadata.filter_metadata` this dialect uses
/// to carry the usage-filter dialect -- must match
/// `proxy_config::lower::USAGE_DIALECT_METADATA_KEY` exactly, for the same
/// "the two crates only agree by convention" reason as
/// [`PROVIDER_AUTH_METADATA_KEY`] above (protos never cross the
/// `proxy-config`/`proxy-xds` boundary, so there is no shared Rust type to
/// pin either string to).
const USAGE_DIALECT_METADATA_KEY: &str = "io.llmproxy.usage";

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
        ProviderType::AzureOpenai => ("api-key".to_string(), key),
        _ => ("authorization".to_string(), format!("Bearer {key}")),
    }))
}

/// The token-extraction dialect this provider's responses speak.
///
/// Anthropic has its own response and SSE shape; everything else — OpenAI
/// itself and the openai-compatible upstreams (vLLM, Ollama, TGI) — speaks
/// OpenAI's. That is the same `_ =>` fallback [`auth_header`] uses, for the
/// same reason: "openai-compatible" is a statement about the wire format.
///
/// Getting this wrong is worse than leaving it unset. The Anthropic scanner
/// fed OpenAI SSE simply finds nothing and reports `None`, but the OpenAI
/// parser on an Anthropic body can *partially* match — which would bill a
/// customer against a number nobody computed correctly.
/// The single dialect this provider's CLUSTER carries, for ground rule #6's
/// per-provider carrier.
///
/// This deliberately does NOT call [`usage_dialect`] directly, and that
/// distinction is the whole point of this function. `usage_dialect` derives
/// the dialect from the provider *type* alone, which is only correct for
/// types where the type determines the wire format. For a
/// dialect-ambiguous type ([`ProviderType::dialect_is_ambiguous`]: Vertex
/// and Bedrock, both of which host Anthropic-shaped models alongside
/// others) the type says nothing, and the real answer lives in the explicit
/// `dialect` on a `models.<name>.providers[i]` entry -- exactly what
/// [`resolved_dialect`] reads and what the ROUTE-level carrier
/// (`lower_model_route`) already uses. Deriving the cluster's copy from the
/// type while the route's copy honours the explicit value makes the two
/// carriers disagree precisely for Anthropic-on-Bedrock/Vertex: the cluster
/// would claim `openai`, the usage filter would parse an OpenAI-shaped
/// `usage` object that is not there, read `None`, and -- per the token
/// limiter's fail-open rule -- charge nothing. A silent quota bypass and
/// wrong billing, which is the exact failure mode moving this onto the
/// cluster exists to prevent.
///
/// So: every `models` entry naming this provider is consulted, and they must
/// agree. Disagreement is a hard error with both offending paths named
/// (ground rule #1) rather than a silent pick, because one cluster cannot
/// carry two dialects -- a provider whose endpoint really does speak both
/// wire formats has to be declared as two providers. A provider no `models`
/// entry references falls back to the type-derived answer, which is what the
/// `routes:` surface (no per-entry `dialect` field) uses anyway.
///
/// That fallback is safe because `validate_semantics` now rejects a
/// dialect-ambiguous provider type wherever `routes:` references it
/// (`check_provider_ref`), so a Vertex/Bedrock provider can only reach
/// lowering through a `models:` entry that stated `dialect` explicitly --
/// which the walk above finds. Before that check existed this function's
/// fallback answered `openai` for such a provider silently, and the usage
/// parser then read nothing off an Anthropic-shaped response.
fn cluster_usage_dialect(
    config: &SimpleConfig,
    provider_name: &str,
    provider: &Provider,
) -> Result<&'static str, ConfigError> {
    Ok(dialect_from_models(config, provider_name)?
        .map(|(_, dialect)| dialect)
        .unwrap_or_else(|| usage_dialect(provider_name, provider)))
}

/// The `models:`-walk half of [`cluster_usage_dialect`], split out so the
/// validator can ask the question the carriers answer: *does any `models:`
/// entry pin this provider's dialect, and if so which?* `None` means no
/// entry references it at all, and the caller decides what that means --
/// [`cluster_usage_dialect`] falls back to the type-derived answer, while
/// `parse.rs` treats it as fatal for a dialect-ambiguous type, since for
/// those the type-derived answer is a guess (`openai`) rather than a fact.
///
/// Returns the path of the first entry that pinned it alongside the dialect,
/// so an error can name a real location.
pub(crate) fn dialect_from_models(
    config: &SimpleConfig,
    provider_name: &str,
) -> Result<Option<(String, &'static str)>, ConfigError> {
    // Rust note: `models` is a `BTreeMap`, so this walk is in sorted key
    // order -- the error below names a deterministic "first" path rather
    // than whichever entry a hash seed happened to yield.
    // `validate_semantics` already rejected an unknown provider name at every
    // path that can produce one, so this lookup cannot miss for a config that
    // reached lowering; the validator itself calls this only after its own
    // unknown-provider check.
    let Some(provider) = config.providers.get(provider_name) else {
        return Ok(None);
    };
    let mut found: Option<(String, &'static str)> = None;
    for (model_name, model) in &config.models {
        for (i, entry) in model.providers.iter().enumerate() {
            if entry.provider() != provider_name {
                continue;
            }
            // `validate_semantics` already rejected an unresolvable dialect
            // at this exact path, via this exact function -- see
            // `parse.rs`'s `resolved_dialect(..).is_none()` check.
            let Some(dialect) = resolved_dialect(provider_name, provider, entry.dialect()) else {
                continue;
            };
            let path = format!("models.{model_name}.providers[{i}]");
            match &found {
                None => found = Some((path, dialect)),
                Some((first_path, first)) if *first != dialect => {
                    return Err(ConfigError::InvalidValue {
                        field_path: path,
                        reason: format!(
                            "provider `{provider_name}` is used with dialect `{dialect}` here                              but with `{first}` at `{first_path}`; a provider's wire format is                              a property of the upstream itself, so it must be the same                              everywhere the provider is used -- declare two providers if the                              endpoint really serves both"
                        ),
                    });
                }
                Some(_) => {}
            }
        }
    }
    Ok(found)
}

fn usage_dialect(name: &str, provider: &Provider) -> &'static str {
    match provider.effective_type(name) {
        ProviderType::Anthropic => "anthropic",
        _ => "openai",
    }
}

/// A `models:` provider entry's effective dialect (WP-49): an explicit
/// `dialect` always wins; otherwise it is derived via [`usage_dialect`] --
/// but only for provider types whose wire format the type alone determines.
/// `None` means "ambiguous type, no explicit `dialect`" -- `validate_semantics`
/// (`parse.rs`) calls this exact function to reject that at parse time, so a
/// `None` reaching `lower.rs`'s callers should be unreachable; the two
/// checks share this one function instead of two mappings that could drift.
///
/// Rust note: `pub(crate)` (not `pub`), since the only caller outside this
/// module is `parse.rs`, which lives in the same crate.
pub(crate) fn resolved_dialect(
    provider_name: &str,
    provider: &Provider,
    dialect: Option<Dialect>,
) -> Option<&'static str> {
    if let Some(d) = dialect {
        return Some(d.as_str());
    }
    if provider
        .effective_type(provider_name)
        .dialect_is_ambiguous()
    {
        return None;
    }
    Some(usage_dialect(provider_name, provider))
}

/// `observability.force_usage_reporting`, defaulting to `true` both when the
/// key is absent AND when the whole `observability` block is absent --
/// `Observability::force_usage_reporting`'s serde default only covers the
/// former, so the latter has to be handled here.
fn force_usage_reporting(config: &SimpleConfig) -> bool {
    config
        .observability
        .as_ref()
        .map_or_else(crate::model::default_force_usage_reporting, |o| {
            o.force_usage_reporting
        })
}

/// Whether the body-rewrite filter needs to be in the chain at all (WP-45
/// decision 3): either `force_usage_reporting` wants the `include_usage`
/// splice, or the config has `routes`/`models` to route among -- body-based
/// model routing (consumer B) depends on this filter unconditionally, since
/// it's the only thing that ever reads the request body. Both reasons are
/// independent, so this is an OR, not a replacement for
/// [`force_usage_reporting`]: a config with routes but usage reporting
/// turned off still needs the filter present (with `enabled: false`,
/// so consumer A stays off), just for consumer B.
fn needs_body_rewrite_filter(config: &SimpleConfig) -> bool {
    force_usage_reporting(config) || !config.routes.is_empty() || !config.models.is_empty()
}

/// Owned `llmproxy.filters.v0.BodyRewrite` `typed_config` for the body-rewrite
/// filter: `enabled` is the on/off switch for consumer A (the
/// `include_usage` splice) ONLY -- consumer B (body-based model routing)
/// reads the filter's presence in the chain, never this field (WP-45
/// decision 3). `dialect` carries the dialect. Shared by the
/// listener-level entry and every per-route override so the two can never
/// drift in shape.
fn body_rewrite_typed_config(enabled: bool, dialect: &str) -> Value {
    json!({
        "@type": BODY_REWRITE_FILTER_TYPE_URL,
        "enabled": enabled,
        "dialect": dialect,
    })
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

/// `cluster_type.typed_config`'s `@type` for the one custom cluster type
/// this dialect ever emits -- must match
/// `proxy_config::lower::AGGREGATE_CLUSTER_CONFIG_TYPE`, prefixed with
/// `type.googleapis.com/` the way every other `typed_config` in this file
/// is.
const AGGREGATE_CLUSTER_CONFIG_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.clusters.aggregate.v3.ClusterConfig";

/// Lower `rule.provider` + `rule.fallbacks` into the route's `route.cluster`
/// and, if there are fallbacks, the extra aggregate cluster that names them
/// (WP-35 increment 2c). Returns `(route, aggregate_cluster)`; the caller
/// appends `aggregate_cluster` to the bootstrap's `clusters` list alongside
/// the provider clusters.
fn lower_route(
    config: &SimpleConfig,
    index: usize,
    rule: &RouteRule,
    warnings: &mut Vec<ConfigWarning>,
) -> Result<(Value, Option<Value>), ConfigError> {
    let provider_name = &rule.provider.provider;
    let provider = &config.providers[provider_name];
    let up = provider_upstream(provider_name, provider)?;
    // Through `cluster_usage_dialect`, NOT `usage_dialect` directly. The
    // `routes:` surface has no `dialect` field of its own, so the only place
    // a Vertex/Bedrock provider's wire format can be stated is a `models:`
    // entry -- and this walks those. `usage_dialect` alone would answer
    // `openai` for such a provider and silently mis-dialect it; the
    // validator guarantees an ambiguous type has a `models:` entry to find.
    let primary_dialect = cluster_usage_dialect(config, provider_name, provider)?;

    if rule.provider.model.is_some() {
        warnings.push(warning(
            format!("routes[{index}].provider"),
            "model rewrite (`provider/model`) needs the request-body rewriter (WP-35); \
             the original model name is forwarded for now",
        ));
    }

    // WP-35 increment 2c: `provider:{name}` for the primary, then each
    // fallback in listed order -- listed order IS the failover order an
    // aggregate cluster fails over in.
    let mut member_clusters = vec![format!("provider:{provider_name}")];
    for (j, fallback) in rule.fallbacks.iter().enumerate() {
        let fallback_path = format!("routes[{index}].fallbacks[{j}]");
        // `validate_semantics` (parse.rs) already rejected an unknown
        // `fallbacks[j].provider` via `check_provider_ref`, so this index is
        // safe.
        let fallback_provider = &config.providers[&fallback.provider];
        let fallback_dialect =
            cluster_usage_dialect(config, &fallback.provider, fallback_provider)?;
        // A hard error, not a warning: an OpenAI-shaped request body is not
        // valid for Anthropic (and vice versa), and the response would be
        // scanned for tokens by the wrong dialect's parser -- silently
        // producing wrong billing numbers, not just a broken request. The
        // request/response translation that would make a cross-dialect
        // chain work is explicitly later WP-35 scope; failing here at
        // config time is ground rule #1's shape, not laziness.
        if fallback_dialect != primary_dialect {
            return Err(ConfigError::InvalidValue {
                field_path: fallback_path,
                reason: format!(
                    "`{}` speaks the `{fallback_dialect}` dialect, but this route's primary \
                     provider `{provider_name}` speaks `{primary_dialect}` -- a \
                     `{primary_dialect}`-shaped request body is not valid for a \
                     `{fallback_dialect}` upstream, and its response would be parsed for \
                     tokens by the wrong dialect's parser (silently wrong billing numbers); \
                     cross-dialect fallback needs request/response translation, which is \
                     later WP-35 scope. Same-dialect fallbacks (e.g. openai -> an \
                     openai-compatible provider) are supported.",
                    fallback.provider
                ),
            });
        }
        if fallback.model.is_some() {
            warnings.push(warning(
                fallback_path,
                "model rewrite (`provider/model`) needs the request-body rewriter (WP-35); \
                 the original model name is forwarded for now",
            ));
        }
        member_clusters.push(format!("provider:{}", fallback.provider));
    }
    let member_count = member_clusters.len();

    let mut r#match = json!({ "prefix": "/" });
    if let Some(header_matcher) = model_glob_matcher(&rule.model) {
        r#match["headers"] = json!([header_matcher]);
    }

    let idle_timeout = rule
        .idle_timeout
        .unwrap_or(SimpleDuration(std::time::Duration::from_secs(90)));

    // A route with no fallbacks targets its provider cluster directly, same
    // as before this increment. A route WITH fallbacks targets a fresh
    // aggregate cluster instead -- named `fallback:route-{index}`, which
    // cannot collide with a provider cluster's `provider:{name}` (different
    // prefix).
    let (route_cluster, aggregate_cluster) = if rule.fallbacks.is_empty() {
        (format!("provider:{provider_name}"), None)
    } else {
        let aggregate_name = format!("fallback:route-{index}");
        let aggregate = json!({
            "name": aggregate_name,
            // Envoy REQUIRES this on an aggregate cluster -- see
            // `proxy-config::lower::convert_cluster`. It must NOT carry
            // `load_assignment`, `transport_socket`,
            // `typed_extension_protocol_options`, or `metadata`: all five
            // are inert on an aggregate (the member that actually serves a
            // request supplies its own endpoints/TLS/protocol/credentials)
            // and are hard errors on our own strict loader.
            "lb_policy": "CLUSTER_PROVIDED",
            "cluster_type": {
                "name": "envoy.clusters.aggregate",
                "typed_config": {
                    "@type": AGGREGATE_CLUSTER_CONFIG_TYPE_URL,
                    "clusters": member_clusters,
                }
            }
        });
        (aggregate_name, Some(aggregate))
    };

    let mut action = json!({
        "cluster": route_cluster,
        // LLM-safe S4 defaults: no total timeout (0 disables), idle-based guard.
        "timeout": "0s",
        "idle_timeout": idle_timeout.to_string(),
        "host_rewrite_literal": up.host,
    });

    // S3, LLM-safe: retry only what is certainly unserved. Envoy's router
    // never retries once response bytes have streamed downstream.
    let attempts = rule.retries.as_ref().map_or(1, |r| r.attempts);
    // WP-35 increment 2c: `LoadBalancerContext::attempted_clusters` makes
    // each retry against an aggregate pick the NEXT member, so reaching the
    // last of N members needs at least N-1 retries -- below that, a
    // configured fallback would silently never see traffic, which is
    // ground rule #1's "accepted but not honored" shape again.
    let min_retries_for_failover = u32::try_from(member_count - 1).unwrap_or(u32::MAX);
    let num_retries = attempts.max(min_retries_for_failover);
    if num_retries > 0 {
        action["retry_policy"] = json!({
            "retry_on": "connect-failure,refused-stream,reset,retriable-status-codes",
            "num_retries": num_retries,
            "retriable_status_codes": [429, 500, 502, 503],
        });
    }

    let mut route = json!({ "match": r#match, "route": action });

    if matches!(rule.streaming, Some(crate::model::StreamingMode::Strict)) {
        route["metadata"] = json!({
            "filter_metadata": {
                "io.llmproxy.streaming": { "strict": true }
            }
        });
    }

    // Token accounting follows the ROUTE's provider, not the listener's: one
    // listener serves `gpt-*` from OpenAI and `claude-*` from Anthropic, and a
    // single listener-level dialect would be wrong for whichever one it isn't.
    // A bare `Any` is the simpler of the two accepted forms — the
    // `envoy.config.route.v3.FilterConfig` wrapper only buys `is_optional`,
    // and this filter is never optional.
    let mut typed_per_filter_config = json!({
        USAGE_FILTER_NAME: {
            "@type": USAGE_FILTER_TYPE_URL,
            "dialect": primary_dialect,
        }
    });
    // Token accounting follows the ROUTE's provider here too, for the exact
    // same reason as the usage filter above -- one listener can serve
    // `gpt-*` from OpenAI and `claude-*` from Anthropic. A fallback member
    // is guaranteed to share `primary_dialect` (checked above), so this
    // stays correct across a failover too.
    if force_usage_reporting(config) {
        typed_per_filter_config[BODY_REWRITE_FILTER_NAME] =
            body_rewrite_typed_config(true, primary_dialect);
    }
    route["typed_per_filter_config"] = typed_per_filter_config;

    Ok((route, aggregate_cluster))
}

/// The provider-credential headers for this provider: the auth header (if a
/// key is configured), Anthropic's default `anthropic-version` (unless
/// overridden), and every `extra_headers` entry. Called once per provider,
/// from [`lower_provider`] -- these headers now travel on the provider's
/// CLUSTER (`metadata.filter_metadata["io.llmproxy.provider_auth"]`), not
/// the route, so every route/model entry that targets this provider shares
/// exactly the same credential regardless of which one reached it (WP-35;
/// see `ClusterConfig::request_headers_to_add`'s doc comment in
/// `proxy-config/src/ir.rs`).
///
/// Each entry is a plain `{key, value}` object -- the shape
/// `proxy_config::lower::convert_provider_auth_metadata` expects under the
/// `headers` list, simpler than `core.v3.HeaderValueOption` because there is
/// exactly one `append_action` this dialect ever wants
/// (`OverwriteIfExistsOrAdd`, hardcoded on the reading side).
fn provider_headers_to_add(
    provider_name: &str,
    provider: &Provider,
    warnings: &mut Vec<ConfigWarning>,
) -> Result<Vec<Value>, ConfigError> {
    let mut headers_to_add = Vec::new();
    if let Some((key, value)) = auth_header(provider_name, provider, warnings)? {
        headers_to_add.push(json!({ "key": key, "value": value }));
    }
    // Anthropic rejects any request without `anthropic-version`, so the
    // dialect supplies it rather than letting an otherwise-complete provider
    // block fail on every call. This is the opinionated-surface move (ground
    // rule #5): Envoy mode stays permissive, the dialect gets a
    // required-by-the-API header right by default. A user-supplied value in
    // `extra_headers` wins, so pinning a different version stays possible.
    //
    // Rust note: HTTP header names are case-insensitive, so the override
    // check compares lowercased -- `Anthropic-Version` must count as the
    // user having set it, otherwise we would emit the header twice.
    if matches!(
        provider.effective_type(provider_name),
        ProviderType::Anthropic
    ) && !provider
        .extra_headers
        .keys()
        .any(|k| k.eq_ignore_ascii_case(ANTHROPIC_VERSION_HEADER))
    {
        headers_to_add.push(json!({
            "key": ANTHROPIC_VERSION_HEADER,
            "value": DEFAULT_ANTHROPIC_VERSION,
        }));
    }
    for (key, value) in &provider.extra_headers {
        headers_to_add.push(json!({ "key": key, "value": value }));
    }
    Ok(headers_to_add)
}

// -------------------------------------------------------------------- models --

/// A `models:` catalogue key's shape (WP-49 increment 2). The only two legal
/// shapes both fall out of where a trailing `*` sits, so classifying and
/// validating are the same pass -- see [`classify_model_key`].
///
/// The bare catch-all `*` is deliberately NOT a third variant: it is exactly
/// `Prefix("")`, an empty prefix. That is what turns "longest prefix, then
/// catch-all" (two rules to remember) into one: sort prefixes by descending
/// length, and the empty one sorts last for free. See `model_catalog_order`.
///
/// **Shared semantics, not shared code.** `proxy_filters::model_authz::ModelPattern`
/// (WP-50 3a, per-tenant model allow-lists) matches trailing-`*` globs with
/// the identical rule -- exact, or `prefix*` via `str::starts_with`. This
/// crate cannot depend on `proxy-filters` in production code (it is a
/// dev-dependency only, kept out of the dialect's dependency tree -- see
/// `Cargo.toml`), so the matching rule is re-implemented here rather than
/// imported. **The two must keep agreeing on what a pattern means** -- see
/// this increment's report for why a shared crate wasn't built for this yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ModelKeyShape {
    /// No `*` at all -- matches this exact model name, and only this one.
    Exact,
    /// Zero or more literal characters (`prefix`) followed by exactly one
    /// trailing `*` -- matches any model name starting with `prefix`,
    /// `prefix` itself included. An empty `prefix` is the bare `*`.
    Prefix(String),
}

/// Classifies (and validates the shape of) one `models:` catalogue key.
/// Legal shapes: no `*` (exact), or a single trailing `*` (`prefix*`,
/// including the bare `*`). Anything else -- `*` in the middle, more than
/// one `*`, a leading `*` that isn't the whole pattern -- is a load error
/// naming the unsupported form, same as a mid-string glob in `routes[].model`
/// would be accepted (via `safe_regex`) but this narrower catalogue syntax
/// is not: see the module doc on why `models:` keys are deliberately a
/// smaller grammar.
pub(crate) fn classify_model_key(name: &str) -> Result<ModelKeyShape, String> {
    match name.find('*') {
        None => Ok(ModelKeyShape::Exact),
        // The FIRST `*` sits at the last byte -- the only way that can be
        // true is if it is also the ONLY `*` (a second one earlier would be
        // found first). So this one check rules out both "more than one
        // `*`" and "a `*` that isn't trailing" at once.
        Some(pos) if pos == name.len() - 1 => Ok(ModelKeyShape::Prefix(name[..pos].to_string())),
        Some(_) => Err(format!(
            "`{name}` is not a supported model pattern -- `*` may appear at most once, and \
             only as a trailing wildcard (`prefix*`) or alone (`*`); a mid-string `*` (e.g. \
             `*-4o`, `gpt-*-mini`) is not supported here"
        )),
    }
}

/// `models:` entries in WP-49 increment 2's precedence order: exact match
/// wins, then the longest matching prefix, then the (empty-prefix) catch-all
/// -- see [`ModelKeyShape`]'s doc for why that is one sort rule, not two.
///
/// **Why a sort, not a lookup trie, even though the plan's own suggestion is
/// a trie:** the thing that actually resolves one request to one catalogue
/// entry is the Envoy route table this function feeds -- `lower_model`
/// builds an ordinary Envoy route per entry, and Envoy's HTTP connection
/// manager evaluates routes in list order, first match wins, exactly as it
/// already does for the hand-written `routes:` list above. That evaluator
/// is List-shaped, not something this crate can swap for a trie underneath
/// it -- so however this function computes the order, the per-REQUEST cost
/// is Envoy's, unaffected by anything here. What this function owns is
/// purely a load-time question -- "what order do N config entries go into
/// that list" -- and a stable sort answers it in O(n log n) over the
/// catalogue once, at config-load, never per request. A trie would earn its
/// keep if this crate ever resolves a model name to a route ITSELF (a
/// custom filter, bypassing Envoy's route table) rather than emitting one;
/// nothing today does that, so building one now would be a structure with
/// no caller.
///
/// Ties: two DIFFERENT prefixes of equal length can never both match the
/// same request (their Nth character would have to be two different values
/// at once), so the alphabetical tie-break below never actually decides a
/// real match -- it only makes the emitted bootstrap byte-for-byte
/// deterministic. A tie on the SAME prefix text is a duplicate key, already
/// rejected at parse time by `model::deserialize_model_catalog` before this
/// function ever sees it.
///
/// `validate_semantics` has already classified (and would have rejected) an
/// illegal key shape before lowering runs, so `classify_model_key` failing
/// here would mean a config reached lowering that parse-time validation was
/// supposed to stop -- an internal bug, not a user-facing error, hence
/// `.expect` rather than another `Result`.
pub(crate) fn model_catalog_order(config: &SimpleConfig) -> Vec<(&String, &ModelDef)> {
    let mut exact = Vec::new();
    let mut prefixed: Vec<(usize, &String, &ModelDef)> = Vec::new();
    for (name, model) in &config.models {
        match classify_model_key(name).expect("validated: models.<name> has a legal shape") {
            ModelKeyShape::Exact => exact.push((name, model)),
            ModelKeyShape::Prefix(prefix) => prefixed.push((prefix.len(), name, model)),
        }
    }
    // Longest prefix first; alphabetical by name is the deterministic
    // tie-break the doc comment above explains is never load-bearing for
    // correctness, only for a stable bootstrap.
    prefixed.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(b.1)));
    exact.extend(prefixed.into_iter().map(|(_, name, model)| (name, model)));
    exact
}

/// `models.<name>` -> one route and, for a multi-provider alias, one ordered
/// aggregate cluster. Each retry against the aggregate advances to the next
/// provider, so callers select an alias, never a provider.
fn lower_model(
    config: &SimpleConfig,
    name: &str,
    model: &ModelDef,
) -> Result<(Value, Option<Value>), ConfigError> {
    // `validate_semantics` already guarantees `providers` is non-empty and
    // `providers[0]` names a real provider.
    let entry = &model.providers[0];
    let provider_name = entry.provider();
    let provider = &config.providers[provider_name];
    let up = provider_upstream(provider_name, provider)?;

    // `validate_semantics` already rejects an unresolvable dialect (an
    // ambiguous provider type with no explicit `dialect`) at every entry
    // index, via this exact function -- so this can't actually be `None`
    // for a config that reached lowering.
    let dialect = resolved_dialect(provider_name, provider, entry.dialect())
        .expect("validated: models.<name>.providers[0]'s dialect is resolvable");

    let mut r#match = json!({ "prefix": "/" });
    if let Some(header_matcher) = model_glob_matcher(name) {
        r#match["headers"] = json!([header_matcher]);
    }

    let mut members = vec![format!("provider:{provider_name}")];
    for (index, candidate) in model.providers.iter().enumerate().skip(1) {
        let candidate_name = candidate.provider();
        let candidate_provider = &config.providers[candidate_name];
        let candidate_dialect =
            resolved_dialect(candidate_name, candidate_provider, candidate.dialect())
                .expect("validated: models.<name>.providers[i]'s dialect is resolvable");
        if candidate_dialect != dialect {
            return Err(ConfigError::InvalidValue {
                field_path: format!("models.{name}.providers[{index}]"),
                reason: format!(
                    "`{candidate_name}` speaks `{candidate_dialect}`, but the primary provider \
                     `{provider_name}` speaks `{dialect}`; cross-dialect model fallback needs \
                     request/response translation and is not supported"
                ),
            });
        }
        members.push(format!("provider:{candidate_name}"));
    }
    let member_count = members.len();
    let (route_cluster, aggregate_cluster) = if member_count == 1 {
        (format!("provider:{provider_name}"), None)
    } else {
        let aggregate_name = format!("fallback:model-{name}");
        let aggregate = json!({
            "name": aggregate_name,
            "lb_policy": "CLUSTER_PROVIDED",
            "cluster_type": {
                "name": "envoy.clusters.aggregate",
                "typed_config": {
                    "@type": AGGREGATE_CLUSTER_CONFIG_TYPE_URL,
                    "clusters": members,
                }
            }
        });
        (aggregate_name, Some(aggregate))
    };

    let mut action = json!({
        "cluster": route_cluster,
        // Same LLM-safe S4 defaults as `lower_route`: no total timeout,
        // idle-based guard. `models:` entries don't (yet) carry their own
        // `idle_timeout` override, so this is always the 90s default.
        "timeout": "0s",
        "idle_timeout": "90s",
        "host_rewrite_literal": up.host,
    });
    if member_count > 1 {
        action["retry_policy"] = json!({
            "retry_on": "connect-failure,refused-stream,reset,retriable-status-codes",
            "num_retries": member_count - 1,
            "retriable_status_codes": [429, 500, 502, 503],
        });
    }

    let mut route = json!({ "match": r#match, "route": action });

    let mut typed_per_filter_config = json!({
        USAGE_FILTER_NAME: {
            "@type": USAGE_FILTER_TYPE_URL,
            "dialect": dialect,
        }
    });
    if force_usage_reporting(config) {
        typed_per_filter_config[BODY_REWRITE_FILTER_NAME] =
            body_rewrite_typed_config(true, dialect);
    }
    route["typed_per_filter_config"] = typed_per_filter_config;

    Ok((route, aggregate_cluster))
}

// -------------------------------------------------------------------- auth --

/// Validates `auth.keys[i].digest`: exactly 64 lowercase hex characters.
///
/// Mirrors the shape checks `proxy_filters::auth_filter::parse_digest_hex`
/// makes on the SAME value once it reaches the proto -- duplicated rather
/// than shared (protos, and the filter code that reads them, never cross
/// into this crate; ground rule #2), so a malformed digest is rejected HERE,
/// with a dialect path (`auth.keys[i].digest`), before it ever reaches that
/// function's proto path (`typed_config.virtual_keys[i].digest_hex`), which
/// names a field the operator's document doesn't have.
fn validate_digest(digest: &str, path: &str) -> Result<(), ConfigError> {
    if digest.len() != 64 {
        return Err(ConfigError::InvalidValue {
            field_path: path.to_string(),
            reason: format!("must be exactly 64 hex characters, got {}", digest.len()),
        });
    }
    if digest.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(ConfigError::InvalidValue {
            field_path: path.to_string(),
            reason: "must be lowercase hex".to_string(),
        });
    }
    if !digest.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ConfigError::InvalidValue {
            field_path: path.to_string(),
            reason: "must contain only hex characters (0-9, a-f)".to_string(),
        });
    }
    Ok(())
}

/// `auth` -> at most one `llmproxy.auth` `http_filters` entry (WP-50
/// increment 2a-iii). All validation happens HERE, with dialect paths
/// (`auth.keys[0].digest`) -- never `auth_filter::parse_config`'s proto paths
/// (`typed_config.virtual_keys[0].digest_hex`), which the operator's document
/// doesn't have a `typed_config` to point into. This is also why the file
/// read for `hmac_secret_file` happens here rather than being deferred to
/// that function: an unreadable secret file should fail at `translate`/load
/// time naming `auth.hmac_secret_file`, not at listener-bind time naming a
/// proto field nobody wrote.
fn lower_auth(
    config: &SimpleConfig,
    warnings: &mut Vec<ConfigWarning>,
) -> Result<Option<Value>, ConfigError> {
    let Some(auth) = &config.auth else {
        return Ok(None);
    };

    let hmac_secret = match (&auth.hmac_secret, &auth.hmac_secret_file) {
        (Some(secret), None) => {
            if secret.is_empty() {
                return Err(ConfigError::InvalidValue {
                    field_path: "auth.hmac_secret".to_string(),
                    reason: "must not be empty (an empty secret would make every credential \
                             digest effectively unkeyed)"
                        .to_string(),
                });
            }
            json!({ "inline_string": secret })
        }
        (None, Some(file)) => {
            // Same wording as `api_key_file`'s warning -- see that field's
            // comment in `lower_provider`/`auth_header`.
            warnings.push(warning(
                "auth.hmac_secret_file",
                "the key file is read once at startup; hot reload lands with WP-35",
            ));
            // Read once, here, purely to validate (readable, non-empty) with
            // a dialect-scoped error -- the CONTENTS are discarded, never
            // echoed, and never folded into `hmac_secret`: the lowered
            // config keeps `filename` (not `inline_string`), so the real
            // proxy reads this file again itself at listener-bind time
            // (`auth_filter::parse_hmac_secret`), exactly once per restart,
            // same as `api_key_file` today.
            let contents = std::fs::read_to_string(file).map_err(|e| ConfigError::Io {
                path: file.clone(),
                reason: e.to_string(),
            })?;
            if contents.trim_end_matches(['\n', '\r']).is_empty() {
                return Err(ConfigError::InvalidValue {
                    field_path: "auth.hmac_secret_file".to_string(),
                    reason: "must not be empty (an empty secret would make every credential \
                             digest effectively unkeyed)"
                        .to_string(),
                });
            }
            json!({ "filename": file })
        }
        (None, None) => {
            return Err(ConfigError::InvalidValue {
                field_path: "auth".to_string(),
                reason: "set either hmac_secret or hmac_secret_file".to_string(),
            });
        }
        (Some(_), Some(_)) => {
            return Err(ConfigError::InvalidValue {
                field_path: "auth".to_string(),
                reason: "set either hmac_secret or hmac_secret_file, not both".to_string(),
            });
        }
    };

    // Rust note: these two maps remember which earlier index first used a
    // given `id`/`digest`, so a duplicate error can name the SECOND
    // (offending) index -- same shape as `auth_filter::parse_config`'s
    // `seen_key_ids`/`seen_digests`, kept independent per ground rule #2.
    let mut seen_ids: HashMap<&str, usize> = HashMap::new();
    let mut seen_digests: HashMap<&str, usize> = HashMap::new();
    let mut virtual_keys = Vec::with_capacity(auth.keys.len());

    for (i, key) in auth.keys.iter().enumerate() {
        let path = format!("auth.keys[{i}]");
        if key.id.is_empty() {
            return Err(ConfigError::InvalidValue {
                field_path: format!("{path}.id"),
                reason: "must not be empty".to_string(),
            });
        }
        if key.tenant.is_empty() {
            return Err(ConfigError::InvalidValue {
                field_path: format!("{path}.tenant"),
                reason: "must not be empty".to_string(),
            });
        }
        validate_digest(&key.digest, &format!("{path}.digest"))?;

        if let Some(&first) = seen_ids.get(key.id.as_str()) {
            return Err(ConfigError::InvalidValue {
                field_path: format!("{path}.id"),
                reason: format!("duplicate `id`; already used at index {first}"),
            });
        }
        if let Some(&first) = seen_digests.get(key.digest.as_str()) {
            return Err(ConfigError::InvalidValue {
                field_path: format!("{path}.digest"),
                reason: format!(
                    "duplicate `digest`; already used at index {first} (two records for one \
                     digest means one is unreachable, and which one wins would depend on \
                     config order)"
                ),
            });
        }
        seen_ids.insert(&key.id, i);
        seen_digests.insert(&key.digest, i);

        virtual_keys.push(json!({
            "key_id": key.id,
            "tenant": key.tenant,
            "digest_hex": key.digest,
            "revoked": key.revoked,
        }));
    }

    if auth.keys.is_empty() {
        // Legal (fail closed is the correct reading of "authentication is
        // enabled, and no credential is valid"), but almost certainly not
        // what the operator meant -- ground rule #1's "warn, don't silently
        // accept" shape for a value that parses fine but does nothing.
        warnings.push(warning(
            "auth.keys",
            "empty -- this `auth:` block authenticates nothing and therefore refuses every \
             request (fail closed); add at least one key, or remove `auth:` entirely",
        ));
    }

    Ok(Some(json!({
        "name": AUTH_FILTER_NAME,
        "typed_config": {
            "@type": AUTH_FILTER_TYPE_URL,
            "hmac_secret": hmac_secret,
            "virtual_keys": virtual_keys,
        }
    })))
}

// ------------------------------------------------------------------ limits --

/// `limits` -> at most one `llmproxy.token_limit` `http_filters` entry.
///
/// The dialect's `limits` surface is richer than what `token_limit_filter`
/// (WP-34 increment 2) enforces today: that filter is a thin slice — a
/// single global token-total budget, bucketed on `(route name, the
/// `authorization` header)`, no per-descriptor config. So exactly one shape
/// lowers for real: `key: header:authorization` with `tokens_per_minute`
/// set. Everything else -- `global`/`client-ip` keys, any other header,
/// `requests_per_minute`, `concurrent_sessions`, `models` -- is recorded in
/// the dialect but not enforced yet, and gets an explicit per-field warning
/// naming its exact dotted path (ground rule #1: never silently drop a
/// field). Only the FIRST supported entry is honored -- the filter has room
/// for exactly one budget rule -- and any later one is warned about too.
fn lower_limits(
    config: &SimpleConfig,
    warnings: &mut Vec<ConfigWarning>,
) -> Result<Option<Value>, ConfigError> {
    let mut token_limit_filter: Option<Value> = None;

    for (i, limit) in config.limits.iter().enumerate() {
        let path = format!("limits[{i}]");

        // `key: tenant` needs an `auth:` block to mean anything -- without
        // one, nothing authenticates a tenant, so the limiter would silently
        // fall back to bucketing on the client-supplied `authorization`
        // header (see `token_limit_filter`'s module doc, "bucket key" table)
        // while the config claims "per tenant". Ground rule #1: a hard
        // error, not a warning -- this is a config that lies about what it
        // enforces, not merely a feature that isn't wired up yet.
        if matches!(&limit.key, LimitKey::Tenant) && config.auth.is_none() {
            return Err(ConfigError::InvalidValue {
                field_path: format!("{path}.key"),
                reason: "`key: tenant` requires an `auth:` block; with none configured, \
                         nothing would authenticate a tenant, and the limiter would silently \
                         fall back to bucketing on the client-supplied `authorization` header \
                         instead -- add `auth:`, or use a different key"
                    .to_string(),
            });
        }
        // The inverse mismatch: an `auth:` block changes what a HEADER key
        // actually buckets on at runtime (the limiter prefers the
        // authenticated tenant whenever one exists -- see
        // `token_limit_filter`'s bucket-key table), regardless of which
        // header this config names. `key: header:authorization` still
        // *lowers* (it remains the one enforced header key absent auth), so
        // this is a warning, not an error: it tells the truth about what
        // will actually happen rather than what the config's key literally
        // says.
        if let LimitKey::Header(name) = &limit.key {
            if config.auth.is_some() {
                warnings.push(warning(
                    format!("{path}.key"),
                    format!(
                        "`header:{name}` is recorded, but with `auth:` configured the token \
                         limiter buckets on the authenticated tenant regardless of this header \
                         -- write `key: tenant` to say what will actually happen"
                    ),
                ));
            }
        }

        let key_supported = matches!(
            &limit.key,
            LimitKey::Header(name) if name.eq_ignore_ascii_case(ENFORCED_LIMIT_HEADER)
        ) || matches!(&limit.key, LimitKey::Tenant);
        if !key_supported {
            let key_desc = match &limit.key {
                LimitKey::Global => "`global`".to_string(),
                LimitKey::ClientIp => "`client-ip`".to_string(),
                LimitKey::Header(name) => format!("`header:{name}`"),
                // Unreachable: `key_supported` is always true for `Tenant`
                // once we reach here (the hard error above already returned
                // for the unauthenticated case). Kept for match
                // exhaustiveness, not because this arm can fire.
                LimitKey::Tenant => "`tenant`".to_string(),
            };
            warnings.push(warning(
                format!("{path}.key"),
                format!(
                    "{key_desc} is not enforced; the token limiter (WP-34) derives its \
                     bucket key from the authenticated tenant when there is one and from \
                     the `{ENFORCED_LIMIT_HEADER}` header otherwise, and has no per-key \
                     configurability, so only `key: tenant` (with `auth:` configured) and \
                     `key: header:{ENFORCED_LIMIT_HEADER}` are enforced today"
                ),
            ));
        }

        if let Some(tokens_per_minute) = limit.tokens_per_minute {
            if key_supported {
                if token_limit_filter.is_some() {
                    warnings.push(warning(
                        format!("{path}.tokens_per_minute"),
                        "not enforced; the token limiter emits at most one budget per \
                         listener, and an earlier `limits` entry already claimed it",
                    ));
                } else {
                    let max_tokens = u32::try_from(tokens_per_minute.0).map_err(|_| {
                        ConfigError::InvalidValue {
                            field_path: format!("{path}.tokens_per_minute"),
                            reason: format!(
                                "`{}` exceeds the token limiter's maximum ({})",
                                tokens_per_minute.0,
                                u32::MAX
                            ),
                        }
                    })?;
                    // 60s fixed window: `token_limit_filter::parse_config`
                    // derives its window as `max_tokens / fill_rate` seconds,
                    // so a per-*minute* dialect value needs `fill_rate =
                    // max_tokens / 60.0` to land on a 60-second window.
                    let fill_rate = f64::from(max_tokens) / 60.0;
                    token_limit_filter = Some(json!({
                        "name": TOKEN_LIMIT_FILTER_NAME,
                        "typed_config": {
                            "@type": TOKEN_LIMIT_FILTER_TYPE_URL,
                            "max_tokens": max_tokens,
                            "fill_rate": fill_rate,
                        }
                    }));
                }
            }
            // else: the key warning above already explains why this
            // `tokens_per_minute` value produces no enforcement.
        }

        if limit.requests_per_minute.is_some() {
            warnings.push(warning(
                format!("{path}.requests_per_minute"),
                "not enforced; the token limiter enforces total token budgets, not a \
                 request-rate cap -- that would be a different feature",
            ));
        }
        if limit.concurrent_sessions.is_some() {
            warnings.push(warning(
                format!("{path}.concurrent_sessions"),
                "not enforced; concurrent-session limits land with WP-37",
            ));
        }
        if !limit.models.is_empty() {
            warnings.push(warning(
                format!("{path}.models"),
                "not enforced; the token limiter has no per-model scoping today",
            ));
        }
    }

    Ok(token_limit_filter)
}

// ------------------------------------------------------------- access logs --

/// `observability.access_logs` -> a single `envoy.config.accesslog.v3.AccessLog`
/// entry, sink-selected by `output` (`stdout`/`stderr`/a file path).
fn lower_access_log(access_logs: &AccessLogs) -> Value {
    // Rust note: `log_format` is a `SubstitutionFormatString` `Value`, built
    // once here and reused by whichever sink below embeds it — the three
    // sinks differ only in `name`/`@type` (and the file sink's extra `path`).
    let log_format = match access_logs.format {
        LogFormat::Text => json!({ "text_format": ACCESS_LOG_TEXT_FORMAT }),
        LogFormat::Json => json!({
            "json_format": {
                "start_time": "%START_TIME%",
                "method": "%REQ(:METHOD)%",
                "path": "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%",
                "protocol": "%PROTOCOL%",
                "response_code": "%RESPONSE_CODE%",
                "response_flags": "%RESPONSE_FLAGS%",
                "bytes_received": "%BYTES_RECEIVED%",
                "bytes_sent": "%BYTES_SENT%",
                "duration_ms": "%DURATION%",
                "request_id": "%REQ(X-REQUEST-ID)%",
                "authority": "%REQ(:AUTHORITY)%",
                "upstream_host": "%UPSTREAM_HOST%",
                "llm_input_tokens": "%LLM_INPUT_TOKENS%",
                "llm_cached_tokens": "%LLM_CACHED_TOKENS%",
                "llm_cache_creation_tokens": "%LLM_CACHE_CREATION_TOKENS%",
                "llm_output_tokens": "%LLM_OUTPUT_TOKENS%",
                "llm_total_tokens": "%LLM_TOTAL_TOKENS%",
                // TTFT and TPOT are a pair -- see ACCESS_LOG_TEXT_FORMAT's
                // doc for why neither is useful alone. `max_stall` is the
                // tail of the TPOT distribution rather than the mean, which
                // is what catches a stream that delivered on average fine
                // while stalling badly once; `response_chunks` is what makes
                // a TPOT value interpretable (a mean over 2 chunks is noise).
                "llm_ttft_ms": "%LLM_TTFT%",
                "llm_tpot_ms": "%LLM_TPOT%",
                "llm_max_stall_ms": "%LLM_MAX_STALL%",
                "llm_response_chunks": "%LLM_RESPONSE_CHUNKS%",
                "llm_key_id": "%LLM_KEY_ID%",
                "llm_tenant": "%LLM_TENANT%",
                "llm_user_id": "%LLM_USER_ID%",
                "llm_requested_model": "%LLM_REQUESTED_MODEL%",
                "llm_selected_model": "%LLM_SELECTED_MODEL%",
                "llm_rate_card_version": "%LLM_RATE_CARD_VERSION%",
                "selected_provider": "%UPSTREAM_CLUSTER%",
                "llm_list_cost_nanodollars": "%LLM_LIST_COST%",
            }
        }),
    };

    match access_logs.output.as_str() {
        "stdout" => json!({
            "name": "envoy.access_loggers.stdout",
            "typed_config": { "@type": STDOUT_ACCESS_LOG_TYPE_URL, "log_format": log_format },
        }),
        "stderr" => json!({
            "name": "envoy.access_loggers.stderr",
            "typed_config": { "@type": STDERR_ACCESS_LOG_TYPE_URL, "log_format": log_format },
        }),
        path => json!({
            "name": "envoy.access_loggers.file",
            "typed_config": {
                "@type": FILE_ACCESS_LOG_TYPE_URL,
                "path": path,
                "log_format": log_format,
            },
        }),
    }
}

// ------------------------------------------------------------------ tracing --

/// Namespace key under `Bootstrap.node.metadata` this dialect uses to carry
/// `observability.tracing` -- must equal
/// `proxy_config::lower::TRACING_METADATA_KEY` exactly, for the same
/// dependency-tree reason as `USAGE_FILTER_TYPE_URL` above (this crate never
/// links `proxy-config`'s internals, only its JSON surface). Unlike the
/// filter type URLs above, there is no separate string-literal pin test for
/// this constant (nor for `PROVIDER_AUTH_METADATA_KEY`/
/// `USAGE_DIALECT_METADATA_KEY` in `lower_provider` below, which use the same
/// pattern): `dialect.rs`'s end-to-end tests call `proxy_config::build_snapshot`
/// directly on this crate's lowered output, so a drift here shows up as that
/// round trip failing to populate `ConfigSnapshot::tracing` at all, which is
/// a stronger signal than a literal string compare.
const TRACING_METADATA_KEY: &str = "io.llmproxy.tracing";

/// `observability.tracing` -> `Bootstrap.node.metadata["io.llmproxy.tracing"]`
/// (JSON object), read back out by
/// `proxy_config::lower::convert_tracing_metadata` into
/// `ConfigSnapshot::tracing` on the way through the identical strict-parse
/// -> PGV -> IR pipeline every Envoy-mode config also goes through. There is
/// no Envoy `Bootstrap` field for this -- `HttpConnectionManager.tracing.
/// provider` is the real Envoy field, and Envoy mode rejects it outright
/// (see `convert_hcm`'s comment: the tracer extension proto isn't compiled
/// into the descriptor pool) -- so this smuggles the value through
/// `Node.metadata` instead, the same channel `lower_provider` uses for
/// per-provider credentials/usage-dialect via `Cluster.metadata`. `Node`
/// (unlike `Cluster`) has no `filter_metadata` wrapper -- its `metadata` is a
/// bare `Struct` -- so the key sits directly under it.
///
/// `otlp_endpoint` non-empty and `sample_ratio` in `0.0..=1.0` are validated
/// here (not left to serde or to the Envoy-mode reader) so a bad dialect
/// value gets a `observability.tracing.<field>` path rather than one scoped
/// to the enclosing block.
fn lower_tracing(tracing: &crate::model::Tracing) -> Result<Value, ConfigError> {
    let endpoint = match &tracing.otlp_endpoint {
        Some(e) if !e.is_empty() => e,
        _ => {
            return Err(ConfigError::InvalidValue {
                field_path: "observability.tracing.otlp_endpoint".to_string(),
                reason: "is required and must not be empty when `observability.tracing` is set"
                    .to_string(),
            });
        }
    };
    if !(0.0..=1.0).contains(&tracing.sample_ratio) {
        return Err(ConfigError::InvalidValue {
            field_path: "observability.tracing.sample_ratio".to_string(),
            reason: "must be between 0.0 and 1.0".to_string(),
        });
    }
    Ok(json!({
        "otlp_endpoint": endpoint,
        "service_name": tracing.service_name,
        "sample_ratio": tracing.sample_ratio,
        "export_deadline": tracing.export_deadline.0.as_secs_f64(),
    }))
}

// ----------------------------------------------------------------- metrics --

/// Namespace key `observability.metrics` is carried through in -- must equal
/// `proxy_config::lower`'s own constant for the same reason
/// [`TRACING_METADATA_KEY`]'s doc gives (it is duplicated as a literal rather
/// than imported because `METRICS_METADATA_KEY` there is private, and
/// `crates/proxy-simple-config/tests/dialect.rs` round-trips this dialect
/// through the real Envoy-mode loader -- so a typo here shows up as a
/// silently-unexported metric block rather than as a compile error).
const METRICS_METADATA_KEY: &str = "io.llmproxy.metrics";

/// `observability.metrics` -> `Bootstrap.node.metadata["io.llmproxy.metrics"]`
/// -> (through the real Envoy-mode loader's
/// `proxy_config::lower::convert_metrics_metadata`) `ConfigSnapshot::metrics`.
///
/// Durations go onto the wire as plain **seconds numbers**, which is what that
/// reader expects: a `google.protobuf.Struct` cannot express a protobuf
/// `Duration`. The dialect's own `SimpleDuration` syntax is resolved here
/// rather than forwarded as a string, so an operator writing `"30s"` in the
/// dialect and an operator writing `30` in raw Envoy config get the same
/// interval.
///
/// The `export_deadline < export_interval` rule is deliberately **not**
/// reimplemented here even though this function already validates
/// `sample_ratio` and `otlp_endpoint` for the tracing block. Two reasons: it is
/// a cross-field rule about what the exporter can actually do (the
/// `MetricsExportConfig::export_deadline` doc owns the reasoning), and this
/// crate's contract is that anything it can express is expressible in Envoy
/// mode too -- duplicating a check the authoritative reader already performs
/// would create two places to keep in agreement and neither would be the one
/// that matters. The Envoy-mode error still names a full dotted path, just one
/// rooted at `node.metadata[...]` rather than at `observability.metrics`.
fn lower_metrics(metrics: &crate::model::Metrics) -> Result<Value, ConfigError> {
    let endpoint = match &metrics.otlp_endpoint {
        Some(e) if !e.is_empty() => e,
        _ => {
            return Err(ConfigError::InvalidValue {
                field_path: "observability.metrics.otlp_endpoint".to_string(),
                reason: "is required and must not be empty when `observability.metrics` is set"
                    .to_string(),
            });
        }
    };
    Ok(json!({
        "otlp_endpoint": endpoint,
        "service_name": metrics.service_name,
        "export_interval": metrics.export_interval.0.as_secs_f64(),
        "export_deadline": metrics.export_deadline.0.as_secs_f64(),
    }))
}

// ----------------------------------------------------------------- listener --

fn lower_listener(
    config: &SimpleConfig,
    routes: Vec<Value>,
    access_log: Option<Value>,
    auth_filter: Option<Value>,
    token_limit_filter: Option<Value>,
    pricing: Option<Value>,
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

    // The listener-level dialect is a fallback that is, in practice,
    // unreachable: every route lowered above carries its own
    // `typed_per_filter_config` override, and a request matching no route gets
    // the dialect's 404 `direct_response` — so it never produces an upstream
    // body for the filter to read. It still has to be *something* valid, so it
    // is the first route's provider rather than a synthetic "unknown" variant
    // that would widen `Dialect` for no gain.
    let default_dialect = config
        .routes
        .first()
        .map(|rule| {
            let name = &rule.provider.provider;
            cluster_usage_dialect(config, name, &config.providers[name])
                .expect("validated: routes[0].provider's dialect resolves")
        })
        .unwrap_or("openai");

    let mut http_filters = Vec::new();
    if let Some(auth_filter) = auth_filter {
        // FIRST, ahead of everything else Lane-H adds -- see
        // `AUTH_FILTER_NAME`'s doc for why (an unauthenticated request must
        // be refused before the body-peek filter buffers it, and the token
        // limiter must see `StreamInfo::auth.tenant` already written).
        http_filters.push(auth_filter);
    }
    if needs_body_rewrite_filter(config) {
        // Decode-path filter, so it must precede the router in config order --
        // decode callbacks run in FORWARD config order (S2.1), and a decode
        // filter placed after the router never runs at all. `enabled` here
        // gates ONLY consumer A (the `include_usage` splice): a config with
        // `routes`/`models` but `force_usage_reporting: false` still needs
        // this filter present, just with the splice off -- WP-45 decision 3.
        http_filters.push(json!({
            "name": BODY_REWRITE_FILTER_NAME,
            "typed_config": body_rewrite_typed_config(force_usage_reporting(config), default_dialect),
        }));
    }
    if let Some(token_limit_filter) = token_limit_filter {
        // Before `llmproxy.usage` in config order -- S2.1 encoder callbacks
        // run in REVERSE config order, and this filter's encode-side job
        // (recording usage against the budget) needs the usage filter's own
        // encode callback to have already run. See
        // `token_limit_filter`'s module doc, "Filter position" section.
        http_filters.push(token_limit_filter);
    }
    let mut usage_config = json!({
        "@type": USAGE_FILTER_TYPE_URL,
        "dialect": default_dialect,
    });
    if let Some(pricing) = pricing {
        usage_config["pricing_json"] = Value::String(pricing.to_string());
    }
    http_filters.push(json!({
        // Before the router, so it is in the encode chain (S2.1: encoder
        // callbacks run in REVERSE config order) and sees response bytes
        // on their way back out.
        "name": USAGE_FILTER_NAME,
        "typed_config": usage_config,
    }));
    http_filters.push(json!({
        "name": "envoy.filters.http.router",
        "typed_config": { "@type": ROUTER_TYPE_URL }
    }));

    let mut hcm = json!({
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
            "http_filters": http_filters,
        }
    });
    if let Some(access_log) = access_log {
        hcm["typed_config"]["access_log"] = json!([access_log]);
    }

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
