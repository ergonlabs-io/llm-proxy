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
const USAGE_FILTER_TYPE_URL: &str = "type.llmproxy.dev/envoy.config.core.v3.DataSource";

/// The body-rewrite filter's name in `http_filters`, gated by
/// `observability.force_usage_reporting` (default `true`). Same
/// name/override-key contract as [`USAGE_FILTER_NAME`].
const BODY_REWRITE_FILTER_NAME: &str = "llmproxy.body_rewrite";

/// Must equal `proxy_filters::body_rewrite_filter::TYPE_URL`. Duplicated for
/// the same dependency-tree reason as [`USAGE_FILTER_TYPE_URL`];
/// `dialect.rs`'s `body_rewrite_filter_type_url_matches_the_filter` pins it.
const BODY_REWRITE_FILTER_TYPE_URL: &str =
    "type.llmproxy.dev/envoy.config.core.v3.RuntimeFeatureFlag";
/// The token-limit filter's name in `http_filters`, emitted only when a
/// `limits` entry actually lowers (see [`lower_limits`]). No per-route
/// override exists for this filter (its module doc: "no per-route config in
/// this increment"), so unlike [`USAGE_FILTER_NAME`] / [`BODY_REWRITE_FILTER_NAME`]
/// this name never appears in a route's `typed_per_filter_config`.
const TOKEN_LIMIT_FILTER_NAME: &str = "llmproxy.token_limit";

/// Must equal `proxy_filters::token_limit_filter::TYPE_URL`. Duplicated for
/// the same dependency-tree reason as [`USAGE_FILTER_TYPE_URL`];
/// `dialect.rs`'s IR-survival test pins the two together the same way.
const TOKEN_LIMIT_FILTER_TYPE_URL: &str =
    "type.llmproxy.dev/envoy.config.core.v3.RateLimitSettings";

/// The only `LimitKey` the thin-slice token limiter enforces: its bucket key
/// is hardcoded to the `authorization` header (see `token_limit_filter`'s
/// module doc, "Config" section).
const ENFORCED_LIMIT_HEADER: &str = "authorization";

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
/// User-Agent), plus the LLM token/TTFT operators — token accounting is the
/// product this proxy exists for, so the dialect's default line carries it.
const ACCESS_LOG_TEXT_FORMAT: &str = concat!(
    "[%START_TIME%] \"%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)% %PROTOCOL%\" ",
    "%RESPONSE_CODE% %RESPONSE_FLAGS% %BYTES_RECEIVED% %BYTES_SENT% %DURATION% ",
    "\"%REQ(X-REQUEST-ID)%\" \"%UPSTREAM_HOST%\" ",
    "llm_tokens=\"%LLM_INPUT_TOKENS%/%LLM_CACHED_TOKENS%/%LLM_CACHE_CREATION_TOKENS%/",
    "%LLM_OUTPUT_TOKENS%/%LLM_TOTAL_TOKENS%\" llm_ttft_ms=\"%LLM_TTFT%\"\n",
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
        clusters.push(lower_provider(name, provider, &mut warnings)?);
    }

    let mut routes = Vec::new();
    let mut has_catch_all = false;
    for (i, rule) in config.routes.iter().enumerate() {
        routes.push(lower_route(config, i, rule, &mut warnings)?);
        has_catch_all |= rule.model == "*";
    }
    // `models:` entries (WP-49) each get an implicit route on their own
    // name, evaluated after the explicit `routes:` list (first match wins,
    // same S1 rule) and before the 404 backstop.
    for (name, model) in &config.models {
        routes.push(lower_model(config, name, model, &mut warnings)?);
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
    if !config.routes.is_empty() || !config.models.is_empty() {
        warnings.push(warning(
            "routes",
            format!(
                "model routing currently matches the `{MODEL_HEADER}` request header; \
                 body-based model extraction lands with the model-router filter (WP-35)"
            ),
        ));
    }

    let token_limit_filter = lower_limits(config, &mut warnings)?;

    let access_log = config
        .observability
        .as_ref()
        .and_then(|o| o.access_logs.as_ref())
        .map(lower_access_log);
    let listener = lower_listener(
        config,
        routes,
        access_log,
        token_limit_filter,
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

/// `azure-openai`/`vertex`/`bedrock` are named in the taxonomy (WP-49) but
/// have no working way to reach the upstream yet: Vertex needs minted OAuth2
/// with a refresh loop, Bedrock needs per-request SigV4 signing over the
/// canonical request (which must run after body rewriting and so cannot be
/// `request_headers_to_add`), and Azure needs a deployment-name +
/// `api-version` URL template neither `host_rewrite_literal` nor
/// `prefix_rewrite` can express. `None` for the three implemented types.
fn unsupported_credential_scheme(provider_type: ProviderType) -> Option<String> {
    let (gap, detail) = match provider_type {
        ProviderType::Vertex => ("credential scheme", "minted OAuth2 with refresh"),
        ProviderType::Bedrock => ("credential scheme", "per-request SigV4 signing"),
        ProviderType::AzureOpenai => (
            "URL path templating",
            "deployment name + api-version query parameter",
        ),
        ProviderType::Openai | ProviderType::Anthropic | ProviderType::OpenaiCompatible => {
            return None
        }
    };
    Some(format!(
        "provider type `{}` is not yet supported: its {gap} ({detail}) is not implemented \
         (WP-49 increment 2)",
        provider_type.as_str()
    ))
}

fn lower_provider(
    name: &str,
    provider: &Provider,
    warnings: &mut Vec<ConfigWarning>,
) -> Result<Value, ConfigError> {
    // This is a hard load error, not a warning, and that is a deliberate
    // departure from the `limits`/`fallbacks` pattern elsewhere in this
    // file: an unenforced *limit* still serves real traffic, but a provider
    // with no working credential scheme would produce a cluster that 401s
    // on every single request. Failing at load is strictly kinder than
    // failing per-request in production.
    if let Some(reason) = unsupported_credential_scheme(provider.effective_type(name)) {
        return Err(ConfigError::Unimplemented {
            field_path: format!("providers.{name}.type"),
            reason,
        });
    }

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
    let headers_to_add = provider_headers_to_add(name, provider, warnings)?;
    if !headers_to_add.is_empty() {
        cluster["metadata"] = json!({
            "filter_metadata": {
                PROVIDER_AUTH_METADATA_KEY: { "headers": headers_to_add }
            }
        });
    }

    Ok(cluster)
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

/// `envoy.config.core.v3.RuntimeFeatureFlag` shaped `typed_config` for the
/// body-rewrite filter: `default_value` is the on/off switch (proto3-JSON
/// maps a `BoolValue` field to a bare JSON bool), `runtime_key` carries the
/// dialect. Shared by the listener-level entry and every per-route override
/// so the two can never drift in shape.
fn body_rewrite_typed_config(dialect: &str) -> Value {
    json!({
        "@type": BODY_REWRITE_FILTER_TYPE_URL,
        "default_value": true,
        "runtime_key": dialect,
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

    let mut route = json!({ "match": r#match, "route": action });

    // Token accounting follows the ROUTE's provider, not the listener's: one
    // listener serves `gpt-*` from OpenAI and `claude-*` from Anthropic, and a
    // single listener-level dialect would be wrong for whichever one it isn't.
    // A bare `Any` is the simpler of the two accepted forms — the
    // `envoy.config.route.v3.FilterConfig` wrapper only buys `is_optional`,
    // and this filter is never optional.
    let mut typed_per_filter_config = json!({
        USAGE_FILTER_NAME: {
            "@type": USAGE_FILTER_TYPE_URL,
            "inline_string": usage_dialect(provider_name, provider),
        }
    });
    // Token accounting follows the ROUTE's provider here too, for the exact
    // same reason as the usage filter above -- one listener can serve
    // `gpt-*` from OpenAI and `claude-*` from Anthropic.
    if force_usage_reporting(config) {
        typed_per_filter_config[BODY_REWRITE_FILTER_NAME] =
            body_rewrite_typed_config(usage_dialect(provider_name, provider));
    }
    route["typed_per_filter_config"] = typed_per_filter_config;

    Ok(route)
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

/// `models.<name>` -> one route (WP-49). `providers[0]` is the only entry
/// this increment ever uses to serve traffic -- it produces the route,
/// pointed at that entry's provider cluster with that entry's dialect.
/// Every later entry is still fully validated (`validate_semantics` already
/// rejected an unknown provider or an unresolvable dialect at any index, not
/// just 0) but is not yet reachable, so it gets an explicit per-entry
/// warning naming its exact path (ground rule #1) rather than being
/// silently accepted -- selection among providers is WP-35.
fn lower_model(
    config: &SimpleConfig,
    name: &str,
    model: &ModelDef,
    warnings: &mut Vec<ConfigWarning>,
) -> Result<Value, ConfigError> {
    // `validate_semantics` already guarantees `providers` is non-empty and
    // `providers[0]` names a real provider.
    let entry = &model.providers[0];
    let provider_name = entry.provider();
    let provider = &config.providers[provider_name];
    let up = provider_upstream(provider_name, provider)?;

    if entry.model().is_some() {
        warnings.push(warning(
            format!("models.{name}.providers[0]"),
            "the upstream model ID needs the request-body rewriter (WP-35); \
             the client's original model name is forwarded for now",
        ));
    }

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

    let action = json!({
        "cluster": format!("provider:{provider_name}"),
        // Same LLM-safe S4 defaults as `lower_route`: no total timeout,
        // idle-based guard. `models:` entries don't (yet) carry their own
        // `idle_timeout` override, so this is always the 90s default.
        "timeout": "0s",
        "idle_timeout": "90s",
        "host_rewrite_literal": up.host,
    });

    let mut route = json!({ "match": r#match, "route": action });

    let mut typed_per_filter_config = json!({
        USAGE_FILTER_NAME: {
            "@type": USAGE_FILTER_TYPE_URL,
            "inline_string": dialect,
        }
    });
    if force_usage_reporting(config) {
        typed_per_filter_config[BODY_REWRITE_FILTER_NAME] = body_rewrite_typed_config(dialect);
    }
    route["typed_per_filter_config"] = typed_per_filter_config;

    for i in 1..model.providers.len() {
        warnings.push(warning(
            format!("models.{name}.providers[{i}]"),
            "not yet selectable; only providers[0] is used to serve traffic until the \
             model router (WP-35) can choose among them",
        ));
    }

    Ok(route)
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

        let key_supported = matches!(
            &limit.key,
            LimitKey::Header(name) if name.eq_ignore_ascii_case(ENFORCED_LIMIT_HEADER)
        );
        if !key_supported {
            let key_desc = match &limit.key {
                LimitKey::Global => "`global`".to_string(),
                LimitKey::ClientIp => "`client-ip`".to_string(),
                LimitKey::Header(name) => format!("`header:{name}`"),
            };
            warnings.push(warning(
                format!("{path}.key"),
                format!(
                    "{key_desc} is not enforced; the token limiter (WP-34) hardcodes its \
                     bucket key to the `{ENFORCED_LIMIT_HEADER}` header, so only \
                     `key: header:{ENFORCED_LIMIT_HEADER}` limits are enforced today"
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
                "llm_ttft_ms": "%LLM_TTFT%",
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

// ----------------------------------------------------------------- listener --

fn lower_listener(
    config: &SimpleConfig,
    routes: Vec<Value>,
    access_log: Option<Value>,
    token_limit_filter: Option<Value>,
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
            usage_dialect(name, &config.providers[name])
        })
        .unwrap_or("openai");

    let mut http_filters = Vec::new();
    if force_usage_reporting(config) {
        // Decode-path filter, so it must precede the router in config order --
        // decode callbacks run in FORWARD config order (S2.1), and a decode
        // filter placed after the router never runs at all.
        http_filters.push(json!({
            "name": BODY_REWRITE_FILTER_NAME,
            "typed_config": body_rewrite_typed_config(default_dialect),
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
    http_filters.push(json!({
        // Before the router, so it is in the encode chain (S2.1: encoder
        // callbacks run in REVERSE config order) and sees response bytes
        // on their way back out.
        "name": USAGE_FILTER_NAME,
        "typed_config": {
            "@type": USAGE_FILTER_TYPE_URL,
            "inline_string": default_dialect,
        }
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
