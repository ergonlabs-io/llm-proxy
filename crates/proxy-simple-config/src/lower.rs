//! Lowering: dialect -> Envoy bootstrap resources.
//!
//! Providers lower to clusters; routes and model aliases lower to Envoy route
//! tables and aggregate clusters. Provider credentials, host, and usage dialect
//! stay on the selected cluster so failover uses that provider's settings.
//! LLM defaults disable total route timeouts and bound idle waits; the resulting
//! bootstrap uses the same strict parse, validation, and IR pipeline as Envoy
//! mode. Accepted but unenforced features produce warnings.

use std::collections::HashMap;
use std::time::Duration;

use proxy_config::{ConfigError, ConfigWarning, LoadedBootstrap};
use serde_json::{json, Value};

use crate::model::*;
use crate::parse::parse_host_port;

mod chargeback;
mod jwt;

/// The request header the route table matches models against. Populated
/// The body-rewrite filter populates this from the request body and removes
/// any client-supplied value before routing.
pub const MODEL_HEADER: &str = "x-llmproxy-model";

const DOWNSTREAM_CONNECTIONS_TYPE_URL: &str = "type.googleapis.com/envoy.extensions.resource_monitors.downstream_connections.v3.DownstreamConnectionsConfig";
const HCM_TYPE_URL: &str = "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager";
const ROUTER_TYPE_URL: &str = "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router";

/// Authentication runs before body rewriting and token limiting, so denial
/// precedes body inspection and limits use the resolved tenant. The config
/// lowerer enforces this order; auth has no per-route override.
const AUTH_FILTER_NAME: &str = "llmproxy.auth";

/// Must equal `proxy_filters::model_authz_filter::TYPE_URL`; pinned by
/// `tests/auth.rs`. Same dependency-tree reason as [`USAGE_FILTER_TYPE_URL`].
const MODEL_AUTHZ_FILTER_TYPE_URL: &str = "type.llmproxy.dev/llmproxy.filters.v0.ModelAuthz";

/// Must equal `proxy_filters::object_ownership_filter::TYPE_URL`; pinned by
/// `tests/auth_enforce.rs`.
const OBJECT_OWNERSHIP_FILTER_TYPE_URL: &str =
    "type.llmproxy.dev/llmproxy.filters.v0.ObjectOwnership";

/// The provider object collections `auth` protects, recorded on every
/// create and kept until removed (ADR-0013 §4). These are endpoint shapes,
/// not providers: a POST to the path returns an object with a top-level
/// `id`, and `<path>/<id>` names that object.
const OBJECT_COLLECTIONS: [&str; 8] = [
    "/v1/files",
    "/v1/batches",
    "/v1/messages/batches",
    "/v1/uploads",
    "/v1/vector_stores",
    "/v1/assistants",
    "/v1/containers",
    "/v1/conversations",
];

/// Request-body members that name a provider object (ADR-0013 §3).
const OBJECT_REFERENCE_MEMBERS: [&str; 12] = [
    "file_id",
    "*_file_id",
    "file_ids",
    "*_file_ids",
    "training_file",
    "validation_file",
    "previous_response_id",
    "vector_store_ids",
    "assistant_id",
    "thread_id",
    "container",
    "conversation",
];

/// Response members that name objects created for the caller (ADR-0013 §2):
/// a batch's files, a completed upload's file, a fine-tuning job's result
/// files, and the thread `POST /v1/threads/runs` creates.
const OBJECT_OWNED_MEMBERS: [&str; 7] = [
    "file_id",
    "*_file_id",
    "file_ids",
    "*_file_ids",
    "file.id",
    "result_files",
    "thread_id",
];

/// Request members that hold the caller's own data, which may share a
/// reference member's name without naming an object.
const OBJECT_OPAQUE_MEMBERS: [&str; 1] = ["metadata"];

/// Default `auth.stored_output_owner_ttl`: 30 days.
const DEFAULT_STORED_OUTPUT_OWNER_TTL_SECS: u64 = 30 * 24 * 3600;

/// The `llmproxy.object_ownership` typed config the dialect lowers to.
/// Stored responses and stored chat completions are created by inference
/// requests, so their owners expire (ADR-0013 §6) and are recorded only when
/// the request asks the provider to store them.
fn object_ownership_config(owner_ttl: Duration) -> serde_json::Value {
    let ttl = owner_ttl.as_secs();
    json!({
        "@type": OBJECT_OWNERSHIP_FILTER_TYPE_URL,
        "collections": OBJECT_COLLECTIONS,
        "collection": [
            {
                "path": "/v1/responses",
                "endpoints": ["input_tokens"],
                "record": "RECORD_UNLESS_FALSE",
                "record_member": "store",
                "owner_ttl_seconds": ttl,
            },
            {
                "path": "/v1/chat/completions",
                "record": "RECORD_IF_TRUE",
                "record_member": "store",
                "owner_ttl_seconds": ttl,
            },
            { "path": "/v1/threads", "endpoints": ["runs"] },
            { "path": "/v1/fine_tuning/jobs" },
        ],
        "reference_members": OBJECT_REFERENCE_MEMBERS,
        "owned_members": OBJECT_OWNED_MEMBERS,
        "opaque_members": OBJECT_OPAQUE_MEMBERS,
    })
}

/// Must equal `proxy_filters::spend_limit_filter::TYPE_URL`; pinned by
/// `tests/auth.rs`.
const SPEND_LIMIT_FILTER_TYPE_URL: &str = "type.llmproxy.dev/llmproxy.filters.v0.SpendLimit";

/// Longest accepted `auth.keys[].id` / `.tenant`.
const MAX_PRINCIPAL_ID_BYTES: usize = 128;

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

/// The model resolver's name in `http_filters`, emitted only when `auto:` is
/// set. Placed after `llmproxy.body_rewrite`, whose extracted model it reads.
const MODEL_RESOLVER_FILTER_NAME: &str = "llmproxy.model_resolver";

/// Must equal `proxy_filters::model_resolver_filter::TYPE_URL`. Duplicated for
/// the same dependency-tree reason as [`USAGE_FILTER_TYPE_URL`];
/// `tests/auto_model.rs` pins it.
const MODEL_RESOLVER_FILTER_TYPE_URL: &str = "type.llmproxy.dev/llmproxy.filters.v0.ModelResolver";

/// The guardrail's name in `http_filters`, emitted only when `guardrails:` is
/// set. Placed after `llmproxy.model_authz` and before the limiters.
const GUARDRAIL_FILTER_NAME: &str = "llmproxy.guardrail";

/// Must equal `proxy_filters::guardrail_filter::TYPE_URL`. Duplicated for the
/// same dependency-tree reason as [`USAGE_FILTER_TYPE_URL`];
/// `tests/guardrails.rs` pins it.
const GUARDRAIL_FILTER_TYPE_URL: &str = "type.llmproxy.dev/llmproxy.filters.v0.Guardrail";
/// Emitted when a `limits` entry lowers; there is no per-route override.
const TOKEN_LIMIT_FILTER_NAME: &str = "llmproxy.token_limit";

/// Must equal `proxy_filters::token_limit_filter::TYPE_URL`. Duplicated for
/// the same dependency-tree reason as [`USAGE_FILTER_TYPE_URL`];
/// `dialect.rs`'s IR-survival test pins the two together the same way.
const TOKEN_LIMIT_FILTER_TYPE_URL: &str = "type.llmproxy.dev/llmproxy.filters.v0.TokenLimit";

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
/// The dialect picks only `text` or `json`, with no custom format string, so
/// if this line omitted `%LLM_TPOT%`, `%LLM_MAX_STALL%` or
/// `%LLM_RESPONSE_CHUNKS%`, a dialect user could not get them at all.
///
/// `timing_us` is the same reasoning applied to `%COMMON_DURATION%`: it
/// splits the request into consecutive phases, in microseconds, so one line
/// says where the time went. See [`TIMING_PHASES`].
const ACCESS_LOG_TEXT_FORMAT: &str = concat!(
    "[%START_TIME%] \"%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)% %PROTOCOL%\" ",
    "%RESPONSE_CODE% %RESPONSE_FLAGS% %BYTES_RECEIVED% %BYTES_SENT% %DURATION% ",
    "\"%REQ(X-REQUEST-ID)%\" \"%UPSTREAM_HOST%\" ",
    "llm_tokens=\"%LLM_INPUT_TOKENS%/%LLM_CACHED_TOKENS%/%LLM_CACHE_CREATION_TOKENS%/",
    "%LLM_OUTPUT_TOKENS%/%LLM_TOTAL_TOKENS%\" llm_ttft_ms=\"%LLM_TTFT%\" ",
    "llm_tpot_ms=\"%LLM_TPOT%\" llm_max_stall_ms=\"%LLM_MAX_STALL%\" ",
    "llm_response_chunks=\"%LLM_RESPONSE_CHUNKS%\" ",
    "key_id=\"%LLM_KEY_ID%\" tenant=\"%LLM_TENANT%\" user_id=\"%LLM_USER_ID%\" ",
    "requested_model=\"%LLM_REQUESTED_MODEL%\" resolved_model=\"%LLM_RESOLVED_MODEL%\" ",
    "guardrail=\"%LLM_GUARDRAIL%\" ",
    "selected_provider=\"%UPSTREAM_CLUSTER%\" ",
    "selected_model=\"%LLM_SELECTED_MODEL%\" rate_card_version=\"%LLM_RATE_CARD_VERSION%\" ",
    "llm_list_cost_nanodollars=\"%LLM_LIST_COST%\" ",
    "llm_credential_source=\"%LLM_CREDENTIAL_SOURCE%\" ",
    "llm_served_model=\"%LLM_SERVED_MODEL%\" ",
    "llm_usage_completeness=\"%LLM_USAGE_COMPLETENESS%\" llm_cost_kind=\"%LLM_COST_KIND%\" ",
    "llm_upstream_id=\"%LLM_UPSTREAM_ID%\" ",
    "response_code_details=\"%RESPONSE_CODE_DETAILS%\" ",
    "timing_us=\"ds_rx=%COMMON_DURATION(DS_RX_BEG:DS_RX_END:us)% ",
    "pre_upstream=%COMMON_DURATION(DS_RX_END:US_TX_BEG:us)% ",
    "us_tx=%COMMON_DURATION(US_TX_BEG:US_TX_END:us)% ",
    "us_wait=%COMMON_DURATION(US_TX_END:US_RX_BEG:us)% ",
    "resp_head=%COMMON_DURATION(US_RX_BEG:DS_TX_BEG:us)% ",
    "ds_tx=%COMMON_DURATION(DS_TX_BEG:DS_TX_END:us)%\"\n",
);

/// JSON access-log keys for the modality token subsets, the count meters and
/// the price basis (ADR-0010). Each renders `-` when the value is absent.
const MEDIA_FIELDS: [(&str, &str); 8] = [
    ("llm_input_image_tokens", "%LLM_INPUT_IMAGE_TOKENS%"),
    ("llm_output_image_tokens", "%LLM_OUTPUT_IMAGE_TOKENS%"),
    ("llm_input_audio_tokens", "%LLM_INPUT_AUDIO_TOKENS%"),
    ("llm_output_audio_tokens", "%LLM_OUTPUT_AUDIO_TOKENS%"),
    ("llm_images", "%LLM_IMAGES%"),
    ("llm_input_characters", "%LLM_INPUT_CHARACTERS%"),
    ("llm_audio_ms", "%LLM_AUDIO_MS%"),
    ("llm_price_basis", "%LLM_PRICE_BASIS%"),
];

/// The request phases both dialect access-log formats carry, as
/// `(name, %COMMON_DURATION% operator)`, in microseconds and in request order:
///
/// - `ds_rx`: reading the client's request.
/// - `pre_upstream`: the filter chain, routing and, for a new connection, the
///   upstream connect.
/// - `us_tx`: handing the request to the upstream codec.
/// - `us_wait`: the provider's time to response headers.
/// - `resp_head`: the response head's way back through the encode filters.
/// - `ds_tx`: streaming the response body to the client.
///
/// A phase whose points the request never reached renders `-`, for example
/// every upstream phase of a local reply.
///
/// There is no `US_CX_BEG:US_CX_END` phase. A request on a reused connection
/// repeats the connect points from when that connection was dialed (Envoy
/// semantics), so on most requests such a phase shows a cost the request
/// never paid. A connect this request did pay is inside `pre_upstream`.
const TIMING_PHASES: [(&str, &str); 6] = [
    ("ds_rx", "%COMMON_DURATION(DS_RX_BEG:DS_RX_END:us)%"),
    ("pre_upstream", "%COMMON_DURATION(DS_RX_END:US_TX_BEG:us)%"),
    ("us_tx", "%COMMON_DURATION(US_TX_BEG:US_TX_END:us)%"),
    ("us_wait", "%COMMON_DURATION(US_TX_END:US_RX_BEG:us)%"),
    ("resp_head", "%COMMON_DURATION(US_RX_BEG:DS_TX_BEG:us)%"),
    ("ds_tx", "%COMMON_DURATION(DS_TX_BEG:DS_TX_END:us)%"),
];

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

/// Render the lowered bootstrap as YAML (`llm-proxy --mode translate`), with
/// every inline secret replaced by [`REDACTED`] (review M9). `${VAR}`
/// interpolation has already put provider keys, the HMAC secret and the store
/// URL into `config`, and the lowering copies them into header values and
/// `inline_string`s, so printing the raw bootstrap would put them on stdout,
/// in a terminal scrollback or a CI log. The redacted output is still a valid
/// bootstrap; it just does not authenticate anywhere.
/// [`to_envoy_yaml_with_secrets`] is the `--reveal-secrets` form.
pub fn to_envoy_yaml(config: &SimpleConfig) -> Result<(String, Vec<ConfigWarning>), ConfigError> {
    let mut lowered = lower(config)?;
    redact_secrets(&mut lowered.bootstrap, &secret_values(config));
    render_yaml(lowered)
}

/// [`to_envoy_yaml`] without redaction: the bootstrap exactly as `serve`
/// would load it, secrets included. Only for an operator who asked for them
/// (`--reveal-secrets`).
pub fn to_envoy_yaml_with_secrets(
    config: &SimpleConfig,
) -> Result<(String, Vec<ConfigWarning>), ConfigError> {
    render_yaml(lower(config)?)
}

fn render_yaml(lowered: Lowered) -> Result<(String, Vec<ConfigWarning>), ConfigError> {
    let yaml = serde_yaml::to_string(&lowered.bootstrap)
        .map_err(|e| ConfigError::Parse(format!("internal: cannot render YAML: {e}")))?;
    Ok((yaml, lowered.warnings))
}

/// What [`to_envoy_yaml`] prints in place of a secret.
pub const REDACTED: &str = "[REDACTED]";

/// Whether `config` holds any secret inline, i.e. whether [`to_envoy_yaml`]
/// has anything to redact. A secret read from a `*_file` field is not inline:
/// the lowering emits the file's path, never its contents.
pub fn has_inline_secrets(config: &SimpleConfig) -> bool {
    !secret_values(config).is_empty()
}

/// Request headers whose value is a credential when an operator sets them in
/// `providers.<name>.extra_headers`.
const CREDENTIAL_HEADER_NAMES: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
];

/// Every inline secret in `config`, after `${VAR}` interpolation: provider
/// keys and tokens, credential-named `extra_headers`, the auth HMAC secret,
/// and the shared store URL (which may carry a password). Empty values are
/// left out; there is nothing to hide in them and an empty pattern would match
/// everywhere.
fn secret_values(config: &SimpleConfig) -> Vec<String> {
    let mut secrets = Vec::new();
    for provider in config.providers.values() {
        secrets.extend(
            [
                &provider.api_key,
                &provider.access_token,
                &provider.access_key_id,
                &provider.secret_access_key,
                &provider.session_token,
            ]
            .into_iter()
            .flatten()
            .cloned(),
        );
        secrets.extend(
            provider
                .extra_headers
                .iter()
                .filter(|(name, _)| {
                    CREDENTIAL_HEADER_NAMES
                        .iter()
                        .any(|credential| credential.eq_ignore_ascii_case(name))
                })
                .map(|(_, value)| value.clone()),
        );
    }
    if let Some(auth) = &config.auth {
        secrets.extend(auth.hmac_secret.iter().cloned());
        if let Some(shared) = auth.store.as_ref().and_then(|store| store.shared.as_ref()) {
            secrets.extend(shared.url.iter().cloned());
        }
    }
    secrets.retain(|secret| !secret.is_empty());
    // Longest first, so a secret that contains another is replaced whole.
    secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
    secrets.dedup();
    secrets
}

/// Replaces every occurrence of each secret in every string of `value`.
/// Substring, not whole-value, matching: a provider key is lowered into
/// `Bearer <key>` header values, not stored alone.
fn redact_secrets(value: &mut Value, secrets: &[String]) {
    match value {
        Value::String(text) => {
            for secret in secrets {
                if text.contains(secret.as_str()) {
                    *text = text.replace(secret.as_str(), REDACTED);
                }
            }
        }
        Value::Array(items) => items
            .iter_mut()
            .for_each(|item| redact_secrets(item, secrets)),
        Value::Object(members) => members
            .values_mut()
            .for_each(|member| redact_secrets(member, secrets)),
        _ => {}
    }
}

pub fn lower(config: &SimpleConfig) -> Result<Lowered, ConfigError> {
    let mut warnings = Vec::new();

    let mut clusters = Vec::new();
    for (name, provider) in &config.providers {
        clusters.push(lower_provider(config, name, provider, &mut warnings)?);
        if let Some(oauth2) = &provider.oauth2_jwt_bearer {
            clusters.push(lower_token_cluster(name, oauth2)?);
        }
    }

    let mut routes = Vec::new();
    let mut has_catch_all = false;
    for (i, rule) in config.routes.iter().enumerate() {
        let (route, aggregate_cluster) = lower_route(config, i, rule, &mut warnings)?;
        routes.push(route);
        // A route with `fallbacks` lowers an extra
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
    // `models:` entries each get an implicit route on their own
    // name, evaluated after the explicit `routes:` list (first match wins,
    // same S1 rule) and before the 404 backstop.
    // `model_catalog_order` puts them in exact > longest-prefix > `*`
    // precedence order rather than the catalogue's alphabetical key order.
    for (name, model) in model_catalog_order(config) {
        let (route, aggregate_cluster) = lower_model(config, name, model)?;
        routes.push(route);
        if let Some(aggregate_cluster) = aggregate_cluster {
            clusters.push(aggregate_cluster);
        }
    }
    // A bare `*` catalogue entry (the empty-prefix tier) is just
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
    // The model catalogue is served locally from the same immutable snapshot
    // as routing. With model policy enforced, `llmproxy.model_authz` answers
    // first with the caller's permitted subset, so this unfiltered route only
    // answers chains where every routed model is open to every caller.
    let catalog = model_catalog(config);
    if !catalog.is_empty() {
        let data: Vec<Value> = catalog
            .iter()
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

    // The body-rewrite filter (inserted below by
    // `needs_body_rewrite_filter`) now scans the request body and publishes
    // `MODEL_HEADER` from it before routing runs, so `routes`/`models`
    // matching that header is body-derived, not merely a header the client
    // happens to set -- no warning needed here anymore.

    let auth_filter = lower_auth(config, &mut warnings)?;
    warn_unenforced_tenant_controls(config, &mut warnings);
    let token_limit_filter = lower_limits(config)?.or_else(|| {
        // Tenant and key limits live in the admin store, so the limiter must
        // be in the chain whenever `auth` is set, even with no `limits` entry.
        // A filter a `limits` entry already added enforces them as well.
        enforces_tenant_limits(config).then(|| {
            json!({
                "name": TOKEN_LIMIT_FILTER_NAME,
                "typed_config": { "@type": TOKEN_LIMIT_FILTER_TYPE_URL }
            })
        })
    });
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
    bootstrap["overload_manager"] = json!({
        "resource_monitors": [ {
            "name": "envoy.resource_monitors.global_downstream_max_connections",
            "typed_config": {
                "@type": DOWNSTREAM_CONNECTIONS_TYPE_URL,
                "max_active_downstream_connections": max_connections(config),
            }
        } ]
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
    if let Some(ledger) = &config.ledger {
        metadata.insert(LEDGER_METADATA_KEY.to_string(), lower_ledger(ledger)?);
    }
    if let Some(traces) = config
        .observability
        .as_ref()
        .and_then(|o| o.traces.as_ref())
    {
        // Dialect-only rule: without `auth` no tenant exists to opt in, so
        // the block would be inert, and an inert block is a silent accept.
        if config.auth.is_none() {
            return Err(ConfigError::InvalidValue {
                field_path: "observability.traces".to_string(),
                reason: "requires auth: tenants opt in through tenant policy".to_string(),
            });
        }
        metadata.insert(TRACES_METADATA_KEY.to_string(), lower_traces(traces)?);
    }
    if !metadata.is_empty() {
        bootstrap["node"] = json!({ "metadata": metadata });
    }

    Ok(Lowered {
        bootstrap,
        warnings,
    })
}

/// Load-time warnings for the tenant controls `auth.enforce` switches off, or
/// that are on but cannot do their job. The admin API still stores policies and
/// budgets, so an operator who opts out must be told, loudly, what is open.
fn warn_unenforced_tenant_controls(config: &SimpleConfig, warnings: &mut Vec<ConfigWarning>) {
    let Some(auth) = &config.auth else {
        return;
    };
    if allows_tenants_without_policy(config) {
        warnings.push(warning(
            "auth.enforce.tenants_without_policy",
            "every authenticated tenant without a stored model policy may use every model; \
             remove this to refuse them until PUT /tenants/{id}/policy grants models",
        ));
    }
    if !auth.enforce.model_policy {
        warnings.push(warning(
            "auth.enforce.model_policy",
            "tenant model allow-lists are NOT enforced: llmproxy.model_authz is omitted, so \
             every authenticated tenant can call every routed model, and the admin API \
             refuses PUT /tenants/{id}/policy",
        ));
    }
    if !auth.enforce.limits && config.limits.is_empty() {
        warnings.push(warning(
            "auth.enforce.limits",
            "tenant and key rate limits are NOT enforced: llmproxy.token_limit is omitted, so \
             the admin API refuses PUT /tenants/{id}/limits and PUT /keys/{id}/limits",
        ));
    }
    if !auth.enforce.object_ownership {
        warnings.push(warning(
            "auth.enforce.object_ownership",
            "provider files and batches are NOT kept to their tenant: \
             llmproxy.object_ownership is omitted, so any tenant that knows another tenant's \
             file or batch ID can read, cancel or delete it, and listing them returns every \
             tenant's",
        ));
    }
    if !auth.enforce.spend {
        warnings.push(warning(
            "auth.enforce.spend",
            "spend budgets are NOT enforced: llmproxy.spend_limit is omitted, so tenant and \
             key budgets never refuse a request, and the admin API refuses \
             PUT /tenants/{id}/budget",
        ));
    } else if config.pricing.is_none() {
        warnings.push(warning(
            "pricing",
            "spend budgets are enforced but no `pricing` rate card is set, so every request \
             costs zero and a budget never fires; set `pricing` to meter spend",
        ));
    }
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
                "the price list file is read at startup and on each config reload; with an `auth` store, the stored rate card wins over a changed file",
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
            let mut value = json!({
                "cached_input_unpriced": entry.cached_input_unpriced,
                "cache_write_unpriced": entry.cache_write_unpriced,
                "provider_type": entry.provider_type,
                "model": entry.model,
            });
            // Rust note: `as_object_mut` borrows the JSON map so keys can be
            // added conditionally. Optional keys are emitted only when set so
            // an existing token card lowers to byte-identical JSON, and its
            // version hash does not change across an upgrade.
            let object = value.as_object_mut().expect("json! object");
            if entry.basis == Some(PriceBasisDef::Images) {
                object.insert("basis".into(), json!("images"));
                object.insert(
                    "image_prices".into(),
                    Value::Array(
                        entry
                            .image_prices
                            .iter()
                            .flatten()
                            .map(|row| {
                                let mut row_value = serde_json::Map::new();
                                if let Some(size) = &row.size {
                                    row_value.insert("size".into(), json!(size));
                                }
                                if let Some(quality) = &row.quality {
                                    row_value.insert("quality".into(), json!(quality));
                                }
                                row_value.insert(
                                    "nanodollars_per_image".into(),
                                    json!(row.nanodollars_per_image),
                                );
                                Value::Object(row_value)
                            })
                            .collect(),
                    ),
                );
            } else {
                object.insert(
                    "tier_mode".into(),
                    json!(match entry.tier_mode.expect("validated") {
                        TierModeDef::WholeRequest => "whole_request",
                        TierModeDef::Graduated => "graduated",
                    }),
                );
                object.insert(
                    "tiers".into(),
                    Value::Array(entry.tiers.iter().map(lower_tier).collect()),
                );
            }
            value
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

fn lower_tier(tier: &TierDef) -> Value {
    let mut value = json!({
        "up_to": tier.up_to,
        "input_nanodollars_per_token": tier.input_nanodollars_per_token,
        "cached_input_nanodollars_per_token": tier.cached_input_nanodollars_per_token,
        "cache_write_nanodollars_per_token": tier.cache_write_nanodollars_per_token,
        "output_nanodollars_per_token": tier.output_nanodollars_per_token,
    });
    let object = value.as_object_mut().expect("json! object");
    for (key, rate) in tier_modality_rates(tier) {
        if let Some(rate) = rate {
            object.insert(key.into(), json!(rate));
        }
    }
    value
}

/// The four optional per-modality tier rates, keyed by their wire names.
fn tier_modality_rates(tier: &TierDef) -> [(&'static str, Option<u64>); 4] {
    [
        (
            "image_input_nanodollars_per_token",
            tier.image_input_nanodollars_per_token,
        ),
        (
            "image_output_nanodollars_per_token",
            tier.image_output_nanodollars_per_token,
        ),
        (
            "audio_input_nanodollars_per_token",
            tier.audio_input_nanodollars_per_token,
        ),
        (
            "audio_output_nanodollars_per_token",
            tier.audio_output_nanodollars_per_token,
        ),
    ]
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
        match entry.basis.unwrap_or(PriceBasisDef::Tokens) {
            PriceBasisDef::Tokens => validate_token_entry(entry, &path)?,
            PriceBasisDef::Images => validate_image_entry(entry, &path)?,
        }
    }
    Ok(())
}

fn invalid(field_path: String, reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidValue {
        field_path,
        reason: reason.into(),
    }
}

fn validate_token_entry(entry: &PriceEntryDef, path: &str) -> Result<(), ConfigError> {
    if entry.image_prices.is_some() {
        return Err(invalid(
            format!("{path}.image_prices"),
            "only a `basis: images` entry has image_prices",
        ));
    }
    if entry.tier_mode.is_none() {
        return Err(ConfigError::InvalidValue {
            field_path: format!("{path}.tier_mode"),
            reason: "required; whole_request and graduated have different money semantics".into(),
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
    // Each modality rate is all-or-none across tiers: a tier missing it would
    // price those tokens at the text rate in one band and not in another.
    for (field_index, (field, _)) in tier_modality_rates(&entry.tiers[0]).iter().enumerate() {
        let set: Vec<bool> = entry
            .tiers
            .iter()
            .map(|tier| tier_modality_rates(tier)[field_index].1.is_some())
            .collect();
        if set.iter().any(|&s| s) && !set.iter().all(|&s| s) {
            let tier_index = set.iter().position(|&s| !s).expect("some tier lacks it");
            return Err(invalid(
                format!("{path}.tiers[{tier_index}].{field}"),
                "must be set on every tier of the entry or on none",
            ));
        }
    }
    Ok(())
}

fn validate_image_entry(entry: &PriceEntryDef, path: &str) -> Result<(), ConfigError> {
    if entry.tier_mode.is_some() {
        return Err(invalid(
            format!("{path}.tier_mode"),
            "not allowed on a `basis: images` entry",
        ));
    }
    if !entry.tiers.is_empty() {
        return Err(invalid(
            format!("{path}.tiers"),
            "not allowed on a `basis: images` entry",
        ));
    }
    // An entry prices only the meters of its basis; a set-but-ignored flag
    // would be a silently ignored field.
    for (flag, name) in [
        (entry.cached_input_unpriced, "cached_input_unpriced"),
        (entry.cache_write_unpriced, "cache_write_unpriced"),
    ] {
        if flag {
            return Err(invalid(
                format!("{path}.{name}"),
                "not allowed on a `basis: images` entry, which prices only images",
            ));
        }
    }
    let Some(rows) = entry
        .image_prices
        .as_deref()
        .filter(|rows| !rows.is_empty())
    else {
        return Err(invalid(
            format!("{path}.image_prices"),
            "required and non-empty on a `basis: images` entry",
        ));
    };
    for (index, row) in rows.iter().enumerate() {
        for (name, value) in [("size", &row.size), ("quality", &row.quality)] {
            if value.as_deref() == Some("") {
                return Err(invalid(
                    format!("{path}.image_prices[{index}].{name}"),
                    "must not be empty",
                ));
            }
        }
        // Two rows of equal specificity that one request could match are
        // ambiguous: identical pairs, or a size-only row with a quality-only
        // row. Rows of different specificity are fine (most specific wins).
        for (earlier, other) in rows[..index].iter().enumerate() {
            let clash = match ((&row.size, &row.quality), (&other.size, &other.quality)) {
                ((a_size, a_quality), (b_size, b_quality))
                    if a_size == b_size && a_quality == b_quality =>
                {
                    true
                }
                ((Some(_), None), (None, Some(_))) | ((None, Some(_)), (Some(_), None)) => true,
                _ => false,
            };
            if clash {
                return Err(invalid(
                    format!("{path}.image_prices[{index}]"),
                    format!(
                        "ambiguous with image_prices[{earlier}]: a request could match both at \
                         the same specificity"
                    ),
                ));
            }
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

/// One upstream cluster for `up`: STATIC for an IP, LOGICAL_DNS for a name,
/// and for `https` a TLS transport that verifies the chain (against `ca_file`
/// or the platform roots) and the host name.
fn endpoint_cluster(
    cluster_name: &str,
    up: &ProviderUpstream,
    ca_file: Option<&str>,
    connect_timeout: SimpleDuration,
) -> Value {
    // IP endpoints can be STATIC; hostnames resolve via LOGICAL_DNS (one
    // address at a time — the right shape for big API hostnames).
    let discovery = if up.host.parse::<std::net::IpAddr>().is_ok() {
        "STATIC"
    } else {
        "LOGICAL_DNS"
    };

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
        let mut validation_context = if let Some(ca_file) = ca_file {
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
    }
    cluster
}

fn lower_provider(
    config: &SimpleConfig,
    name: &str,
    provider: &Provider,
    warnings: &mut Vec<ConfigWarning>,
) -> Result<Value, ConfigError> {
    let up = provider_upstream(name, provider)?;
    let cluster_name = format!("provider:{name}");

    let mut cluster = endpoint_cluster(
        &cluster_name,
        &up,
        provider.ca_file.as_deref(),
        provider
            .connect_timeout
            .unwrap_or(SimpleDuration(std::time::Duration::from_secs(5))),
    );
    if !up.tls && provider.ca_file.is_some() {
        warnings.push(warning(
            format!("providers.{name}.ca_file"),
            "ca_file is ignored for plaintext (http://) providers",
        ));
    }

    // `protocol: http2` is the on-ramp to `proxy-http::upstream_pool`'s h2
    // upstream connection cache -- see this cluster's own
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
    // The Host header follows the CLUSTER, not the
    // route. A route with fallbacks can fail over to a different provider
    // cluster (see `lower_route`'s aggregate-cluster handling), and
    // `host_rewrite_literal` on the ROUTE would still carry the PRIMARY
    // provider's host to whichever member actually serves the request --
    // the exact "value pinned to the routing decision instead of the
    // connection" bug class this code exists to kill. Setting it
    // here too means the member that actually dials the request always
    // supplies its own Host, exactly like its credentials
    // (`router.rs`'s `apply_header_mutations` call applies cluster-level
    // `request_headers_to_add` after the route-level transforms and lets it
    // win on a key collision). This runs for every provider, not only ones
    // used in a fallback chain: a route with no fallbacks already sets the
    // identical value via `host_rewrite_literal`, so this is a no-op there,
    // and one rule is simpler than two.
    headers_to_add.push(json!({ "key": "host", "value": up.host }));
    // This is another instance of AGENTS.md invariant 6: the
    // usage-filter dialect is per-provider too, so it rides onto the CLUSTER
    // alongside credentials and `Host` above rather than staying only on the
    // route's `typed_per_filter_config` -- that route-level copy is left
    // completely unchanged by this change (both carriers must agree; see
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
    // The tenant slot sits in the same object as the operator key, so the
    // router reads both from one cluster. It is computed before the
    // provider-type match so an opted-in Vertex/Bedrock provider is reported
    // at the opt-in field, not at its missing OAuth2 or SigV4 secret.
    // A verify path without a slot would be silently dropped, so refuse it
    // here at the field that set it (AGENTS.md invariant 1).
    if provider.tenant_credential_verify_path.is_some() && !provider.tenant_credentials {
        return Err(ConfigError::InvalidValue {
            field_path: format!("providers.{name}.tenant_credential_verify_path"),
            reason: "requires `tenant_credentials: true`; the verify path is only used by a tenant credential slot".to_string(),
        });
    }
    if provider.tenant_credentials {
        provider_auth["tenant_credential"] =
            tenant_credential_slot(config, name, provider, provider_type)?;
    }
    // Every cluster lowered from this provider gets the policy, aggregate
    // members included (AGENTS.md invariant 6): the policy follows the
    // provider actually dialled, not the route.
    if let Some(fields) = &provider.request_fields {
        provider_auth["request_field_policy"] = request_field_policy(name, fields)?;
    }
    let mut path_template = None;
    match provider_type {
        ProviderType::Vertex => {
            if let Some(oauth2) = &provider.oauth2_jwt_bearer {
                provider_auth["scheme"] = json!("oauth2-jwt-bearer");
                provider_auth["oauth2_jwt_bearer"] = lower_oauth2_jwt_bearer(name, oauth2)?;
            } else {
                let access_token = provider_secret(
                    name,
                    "access_token",
                    provider.access_token.as_ref(),
                    provider.access_token_file.as_ref(),
                    warnings,
                )?;
                provider_auth["scheme"] = json!("vertex-oauth2");
                provider_auth["access_token"] = json!(access_token);
            }
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

/// The cluster a provider's token endpoint is dialled through. Named apart
/// from `provider:` clusters so no provider name can collide with it.
fn token_cluster_name(provider_name: &str) -> String {
    format!("oauth2-token:{provider_name}")
}

/// The token endpoint's cluster, with the same verified TLS a provider gets.
fn lower_token_cluster(
    provider_name: &str,
    oauth2: &OAuth2JwtBearerDef,
) -> Result<Value, ConfigError> {
    let url = crate::parse::parse_token_url(
        &oauth2.token_url,
        &format!("providers.{provider_name}.oauth2_jwt_bearer.token_url"),
    )?;
    let up = ProviderUpstream {
        host: url.host,
        port: url.port,
        tls: url.tls,
    };
    Ok(endpoint_cluster(
        &token_cluster_name(provider_name),
        &up,
        oauth2.ca_file.as_deref(),
        SimpleDuration(std::time::Duration::from_secs(5)),
    ))
}

/// The `oauth2_jwt_bearer` metadata block. The key file is read and checked
/// here so a bad key names its dialect path; the bootstrap carries only the
/// path, and Envoy-mode lowering reads it again.
fn lower_oauth2_jwt_bearer(
    provider_name: &str,
    oauth2: &OAuth2JwtBearerDef,
) -> Result<Value, ConfigError> {
    let key_path = &oauth2.private_key_file;
    let field_path = format!("providers.{provider_name}.oauth2_jwt_bearer.private_key_file");
    let pem = std::fs::read_to_string(key_path).map_err(|e| ConfigError::InvalidValue {
        field_path: field_path.clone(),
        reason: format!("cannot read `{key_path}`: {e}"),
    })?;
    proxy_config::ir::RsaSigningKey::from_pkcs8_pem(&pem).map_err(|reason| {
        ConfigError::InvalidValue {
            field_path,
            reason: format!("`{key_path}` {reason}"),
        }
    })?;
    let mut block = json!({
        "token_cluster": token_cluster_name(provider_name),
        "token_url": oauth2.token_url,
        "issuer": oauth2.issuer,
        "private_key_file": key_path,
        "scopes": oauth2.scopes,
    });
    for (field, value) in [
        ("subject", &oauth2.subject),
        ("key_id", &oauth2.key_id),
        ("audience", &oauth2.audience),
    ] {
        if let Some(value) = value {
            block[field] = json!(value);
        }
    }
    for (field, value) in [
        ("assertion_lifetime_seconds", oauth2.assertion_lifetime),
        ("refresh_before_seconds", oauth2.refresh_before),
        ("request_timeout_seconds", oauth2.timeout),
    ] {
        if let Some(SimpleDuration(duration)) = value {
            block[field] = json!(duration.as_secs());
        }
    }
    Ok(block)
}

/// The load warning for `auth.hmac_secret_file`.
pub const HMAC_SECRET_FILE_WARNING: &str =
    "the secret file is read at startup and again on each SIGHUP reload; a reload that \
     changes the secret is refused, so rotating it takes a restart";

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
                "the credential file is read at startup and again on each SIGHUP reload; to rotate \
                 it, replace the file and reload",
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
                "the key file is read at startup and again on each SIGHUP reload; to rotate it, \
                 replace the file and reload",
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
    let (header, prefix) = api_key_header(provider.effective_type(name));
    Ok(Some((header.to_string(), format!("{prefix}{key}"))))
}

/// The header and value prefix a provider type takes its API key in. Shared
/// by the operator key ([`auth_header`]) and the tenant credential slot
/// ([`tenant_credential_slot`]), so a tenant key is sent exactly where the
/// operator key would have gone (ADR-0007 decision 1).
fn api_key_header(provider_type: ProviderType) -> (&'static str, &'static str) {
    match provider_type {
        ProviderType::Anthropic => ("x-api-key", ""),
        ProviderType::AzureOpenai => ("api-key", ""),
        _ => ("authorization", "Bearer "),
    }
}

/// `providers.<name>.request_fields` as the `request_field_policy` metadata
/// object. Empty names and a name in both lists are refused here, at the
/// dialect path, rather than later at the metadata path.
fn request_field_policy(
    name: &str,
    fields: &crate::model::RequestFields,
) -> Result<serde_json::Value, ConfigError> {
    for (list, names) in [("deny", &fields.deny), ("strip", &fields.strip)] {
        for (i, field) in names.iter().enumerate() {
            if field.is_empty() {
                return Err(ConfigError::InvalidValue {
                    field_path: format!("providers.{name}.request_fields.{list}[{i}]"),
                    reason: "field name must not be empty".to_string(),
                });
            }
        }
    }
    for (i, field) in fields.strip.iter().enumerate() {
        if fields.deny.contains(field) {
            return Err(ConfigError::InvalidValue {
                field_path: format!("providers.{name}.request_fields.strip[{i}]"),
                reason: format!("`{field}` is also in `deny`; choose one"),
            });
        }
    }
    Ok(json!({ "deny": fields.deny, "strip": fields.strip }))
}

/// The `tenant_credential` slot under `io.llmproxy.provider_auth` for a
/// provider that set `tenant_credentials: true` (ADR-0007 decision 1). The
/// slot names the provider label and the header shape from
/// [`api_key_header`]. A cluster can carry a slot only when its credential
/// is a header API key, so Vertex (OAuth2) and Bedrock (SigV4) are rejected
/// here, at the opt-in field. The slot also needs the key ring, because a
/// tenant key cannot be stored without it (ADR-0007 decision 2).
fn tenant_credential_slot(
    config: &SimpleConfig,
    name: &str,
    provider: &Provider,
    provider_type: ProviderType,
) -> Result<Value, ConfigError> {
    let field_path = format!("providers.{name}.tenant_credentials");
    if matches!(provider_type, ProviderType::Vertex | ProviderType::Bedrock) {
        return Err(ConfigError::InvalidValue {
            field_path,
            reason: format!(
                "not supported for `{}` providers: they authenticate with OAuth2 or SigV4, \
                 not a header API key, so their cluster cannot carry a tenant credential",
                provider_type.as_str()
            ),
        });
    }
    if config
        .auth
        .as_ref()
        .and_then(|auth| auth.tenant_credentials.as_ref())
        .is_none()
    {
        return Err(ConfigError::InvalidValue {
            field_path,
            reason: "requires `auth.tenant_credentials` (the key ring that seals tenant \
                     credentials at rest); none is configured"
                .to_string(),
        });
    }
    let (header, prefix) = api_key_header(provider_type);
    let mut slot = json!({ "provider": name, "header": header, "prefix": prefix });
    // Omitted when there is no probe, so the Envoy side lowers it to `None`.
    if let Some(verify_path) = tenant_verify_path(name, provider, provider_type)? {
        slot["verify_path"] = json!(verify_path);
    }
    Ok(slot)
}

/// The `verify_path` for a tenant slot (ADR-0007 decision 10): the explicit
/// `tenant_credential_verify_path`, else a default for the provider types with
/// a known zero-cost `GET`. A provider with `base_url` set gets no default,
/// because the endpoint behind a custom URL may not serve that path.
fn tenant_verify_path(
    name: &str,
    provider: &Provider,
    provider_type: ProviderType,
) -> Result<Option<String>, ConfigError> {
    if let Some(path) = &provider.tenant_credential_verify_path {
        // The rule set lives in `proxy-config`, shared with the Envoy-mode
        // check; only the field path is this dialect's own.
        if let Some(reason) = proxy_config::tenant_credential_verify_path_problem(path) {
            return Err(ConfigError::InvalidValue {
                field_path: format!("providers.{name}.tenant_credential_verify_path"),
                reason,
            });
        }
        return Ok(Some(path.clone()));
    }
    if provider.base_url.is_some() {
        return Ok(None);
    }
    Ok(match provider_type {
        ProviderType::Openrouter => Some("/api/v1/key".to_string()),
        ProviderType::Openai | ProviderType::Anthropic => Some("/v1/models".to_string()),
        _ => None,
    })
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
/// The single dialect this provider's CLUSTER carries, for AGENTS.md invariant 6's
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
/// (AGENTS.md invariant 1) rather than a silent pick, because one cluster cannot
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

/// A `models:` provider entry's effective dialect: an explicit
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

/// Whether the body-rewrite filter needs to be in the chain at all: either
/// `force_usage_reporting` wants the `include_usage`
/// splice, or the config has `routes`/`models` to route among -- body-based
/// model routing (consumer B) depends on this filter unconditionally, since
/// it's the only thing that ever reads the request body. Both reasons are
/// independent, so this is an OR, not a replacement for
/// [`force_usage_reporting`]: a config with routes but usage reporting
/// turned off still needs the filter present (with `enabled: false`,
/// so consumer A stays off), just for consumer B.
fn needs_body_rewrite_filter(config: &SimpleConfig) -> bool {
    force_usage_reporting(config)
        || !config.routes.is_empty()
        || !config.models.is_empty()
        // `llmproxy.model_authz` reads the requested model that this filter
        // publishes; without it every request would look model-less and be
        // refused, even in a config that otherwise needs no body peek.
        || enforces_model_policy(config)
}

/// `auth` is set and `auth.enforce.model_policy` is on: the chain carries
/// `llmproxy.model_authz`.
/// The model IDs `GET /v1/models` lists: every `routes[].model` and `models`
/// key that names one model, sorted and deduplicated. A name with `*` is a
/// routing rule, not a model a client can request by that name, so it is not
/// listed; neither is the `auto` trigger, which is never itself granted.
fn model_catalog(config: &SimpleConfig) -> Vec<String> {
    config
        .routes
        .iter()
        .map(|rule| rule.model.as_str())
        .chain(config.models.keys().map(String::as_str))
        .filter(|name| !name.contains('*'))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn enforces_model_policy(config: &SimpleConfig) -> bool {
    config
        .auth
        .as_ref()
        .is_some_and(|auth| auth.enforce.model_policy)
}

/// `auth.enforce.tenants_without_policy: allow` on a chain that enforces
/// model policy.
fn allows_tenants_without_policy(config: &SimpleConfig) -> bool {
    enforces_model_policy(config)
        && config.auth.as_ref().is_some_and(|auth| {
            auth.enforce.tenants_without_policy == Some(TenantsWithoutPolicy::Allow)
        })
}

/// `auth` is set and `auth.enforce.limits` is on: the chain carries
/// `llmproxy.token_limit` for tenant and key limits.
fn enforces_tenant_limits(config: &SimpleConfig) -> bool {
    config.auth.as_ref().is_some_and(|auth| auth.enforce.limits)
}

/// `auth` is set and `auth.enforce.object_ownership` is on: the chain
/// carries `llmproxy.object_ownership`.
fn enforces_object_ownership(config: &SimpleConfig) -> bool {
    config
        .auth
        .as_ref()
        .is_some_and(|auth| auth.enforce.object_ownership)
}

/// `auth` is set and `auth.enforce.spend` is on: the chain carries
/// `llmproxy.spend_limit`.
fn enforces_spend(config: &SimpleConfig) -> bool {
    config.auth.as_ref().is_some_and(|auth| auth.enforce.spend)
}

/// Owned `llmproxy.filters.v0.BodyRewrite` `typed_config` for the body-rewrite
/// filter: `enabled` is the on/off switch for consumer A (the
/// `include_usage` splice) ONLY -- consumer B (body-based model routing)
/// reads the filter's presence in the chain, never this field. `dialect` carries
/// the dialect. Shared by the
/// listener-level entry and every per-route override so the two can never
/// drift in shape.
fn body_rewrite_typed_config(
    enabled: bool,
    dialect: &str,
    max_output_tokens: Option<u32>,
) -> Value {
    let mut config = json!({
        "@type": BODY_REWRITE_FILTER_TYPE_URL,
        "enabled": enabled,
        "dialect": dialect,
    });
    if let Some(cap) = max_output_tokens {
        config["max_output_tokens"] = json!(cap);
    }
    config
}

/// `auto:` -> `llmproxy.filters.v0.ModelResolver` in-process rules.
fn model_resolver_typed_config(auto: &crate::model::AutoModel) -> Value {
    let mut rules = json!({
        "tenants": auto
            .tenants
            .iter()
            .map(|(tenant, model)| json!({ "tenant": tenant, "model": model }))
            .collect::<Vec<_>>(),
    });
    if let Some(default) = &auto.default {
        rules["default_model"] = json!(default);
    }
    json!({ "@type": MODEL_RESOLVER_FILTER_TYPE_URL, "rules": rules })
}

/// `guardrails:` -> `llmproxy.filters.v0.Guardrail`. Parse validation already
/// guarantees every field this reads.
fn guardrail_typed_config(guardrails: &crate::model::Guardrails) -> Value {
    let check = |check: &crate::model::GuardrailCheck| {
        let http = check.http.as_ref().expect("validated: a backend is set");
        let timeout = http.timeout.expect("validated: a timeout is set").0;
        json!({
            "http": {
                "uri": http.url,
                "timeout_ms": u32::try_from(timeout.as_millis()).expect("validated: fits u32"),
                "max_body_bytes": http.max_body_bytes,
            },
            "failure_mode": match check.failure_mode.expect("validated: a failure mode is set") {
                crate::model::GuardrailFailureMode::Closed => "FAIL_CLOSED",
                crate::model::GuardrailFailureMode::Open => "FAIL_OPEN",
            },
        })
    };
    json!({
        "@type": GUARDRAIL_FILTER_TYPE_URL,
        "default_check": check(guardrails.default.as_ref().expect("validated: default is set")),
        "tenants": guardrails
            .tenants
            .iter()
            .map(|(tenant, c)| json!({ "tenant": tenant, "check": check(c) }))
            .collect::<Vec<_>>(),
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
/// and, if there are fallbacks, the extra aggregate cluster that names them.
/// Returns `(route, aggregate_cluster)`; the caller
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
            "model rewrite (`provider/model`) needs the request-body rewriter, which is not supported yet; \
             the original model name is forwarded for now",
        ));
    }

    // `provider:{name}` for the primary, then each
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
        // chain work is explicitly deferred work; failing here at
        // config time is AGENTS.md invariant 1's shape, not laziness.
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
                     not supported yet. Same-dialect fallbacks (e.g. openai -> an \
                     openai-compatible provider) are supported.",
                    fallback.provider
                ),
            });
        }
        if fallback.model.is_some() {
            warnings.push(warning(
                fallback_path,
                "model rewrite (`provider/model`) needs the request-body rewriter, which is not supported yet; \
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
    // as before fallbacks existed. A route WITH fallbacks targets a fresh
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
    // `LoadBalancerContext::attempted_clusters` makes
    // each retry against an aggregate pick the NEXT member, so reaching the
    // last of N members needs at least N-1 retries -- below that, a
    // configured fallback would silently never see traffic, which is
    // AGENTS.md invariant 1's "accepted but not honored" shape again.
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
            body_rewrite_typed_config(true, primary_dialect, None);
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
/// exactly the same credential regardless of which one reached it
/// (see `ClusterConfig::request_headers_to_add`'s doc comment in
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

/// A `models:` catalogue key's shape. The only two legal
/// shapes both fall out of where a trailing `*` sits, so classifying and
/// validating are the same pass -- see [`classify_model_key`].
///
/// The bare catch-all `*` is deliberately NOT a third variant: it is exactly
/// `Prefix("")`, an empty prefix. That is what turns "longest prefix, then
/// catch-all" (two rules to remember) into one: sort prefixes by descending
/// length, and the empty one sorts last for free. See `model_catalog_order`.
///
/// **Shared semantics, not shared code.** `proxy_control::model_authz::ModelPattern`
/// (per-tenant model allow-lists) matches trailing-`*` globs with
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
    // The schema's key pattern needs at least one character; an empty key
    // would otherwise lower to an exact route for an empty model name.
    if name.is_empty() {
        return Err("a model name must not be empty".to_string());
    }
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

/// `models:` entries in precedence order: exact match
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
    // The per-route override replaces the listener-level config outright, so
    // it must carry the usage switch as well as the cap. A cap alone on a
    // config with usage reporting turned off keeps the splice off.
    let max_output_tokens = model.max_output_tokens;
    if force_usage_reporting(config) || max_output_tokens.is_some() {
        typed_per_filter_config[BODY_REWRITE_FILTER_NAME] =
            body_rewrite_typed_config(force_usage_reporting(config), dialect, max_output_tokens);
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
/// into this crate; AGENTS.md invariant 2), so a malformed digest is rejected HERE,
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

/// `auth` -> at most one `llmproxy.auth` `http_filters` entry. All validation
/// happens HERE, with dialect paths
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
            // Unlike `api_key_file`, a changed secret cannot apply on reload:
            // the auth control plane mints and verifies with the secret it
            // started with, so the proxy refuses that reload.
            warnings.push(warning("auth.hmac_secret_file", HMAC_SECRET_FILE_WARNING));
            // Read once, here, purely to validate (readable, non-empty) with
            // a dialect-scoped error -- the CONTENTS are discarded, never
            // echoed, and never folded into `hmac_secret`: the lowered
            // config keeps `filename` (not `inline_string`), so the real
            // proxy reads this file again itself at listener-bind time
            // (`auth_filter::parse_hmac_secret`) on every build, and a reload
            // compares it with the running secret.
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
    // `seen_key_ids`/`seen_digests`, kept independent per AGENTS.md invariant 2.
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
        // Must equal `proxy_observability::records::MAX_PRINCIPAL_ID_BYTES`
        // (pinned by a test); duplicated because this crate does not depend on
        // the data plane. Over-long ids would be truncated or rejected in
        // request records, so fail at load with the dotted path.
        for (field, value) in [("id", &key.id), ("tenant", &key.tenant)] {
            if value.len() > MAX_PRINCIPAL_ID_BYTES {
                return Err(ConfigError::InvalidValue {
                    field_path: format!("{path}.{field}"),
                    reason: format!(
                        "is {} bytes; the maximum is {MAX_PRINCIPAL_ID_BYTES}",
                        value.len()
                    ),
                });
            }
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
        chargeback::check_key_tags(&key.tags, &format!("{path}.tags"))?;

        let mut virtual_key = json!({
            "key_id": key.id,
            "tenant": key.tenant,
            "digest_hex": key.digest,
            "revoked": key.revoked,
        });
        // Absent when empty, so keys without tags lower byte-identically.
        if !key.tags.is_empty() {
            virtual_key["tags"] = json!(key.tags);
        }
        virtual_keys.push(virtual_key);
    }

    let jwt_providers = jwt::lower_jwt_providers(auth, warnings)?;

    if auth.keys.is_empty() && jwt_providers.is_empty() {
        // Legal (fail closed is the correct reading of "authentication is
        // enabled, and no credential is valid"), but almost certainly not
        // what the operator meant -- AGENTS.md invariant 1's "warn, don't silently
        // accept" shape for a value that parses fine but does nothing.
        warnings.push(warning(
            "auth.keys",
            "empty -- this `auth:` block authenticates nothing and therefore refuses every \
             request (fail closed); add at least one key, or remove `auth:` entirely",
        ));
    }

    if let Some(SimpleDuration(bound)) = auth.max_policy_staleness {
        // The dialect does not expose the poll interval, so the floor is
        // fixed: 2 x the 48 s default, the same rule
        // `auth_filter::parse_max_policy_staleness` applies to the lowered
        // value. Checked here so the error names the dialect path.
        if bound.subsec_nanos() != 0 || bound < std::time::Duration::from_secs(96) {
            return Err(ConfigError::InvalidValue {
                field_path: "auth.max_policy_staleness".to_string(),
                reason: "must be whole seconds and at least 96s (2 x the 48s policy poll), \
                         or a healthy replica would refuse requests between two polls"
                    .to_string(),
            });
        }
    }

    if let Some(SimpleDuration(ttl)) = auth.stored_output_owner_ttl {
        if !auth.enforce.object_ownership {
            return Err(ConfigError::InvalidValue {
                field_path: "auth.stored_output_owner_ttl".to_string(),
                reason: "has no effect with `enforce.object_ownership: false`, which omits the \
                         filter that reads it; remove one of the two"
                    .to_string(),
            });
        }
        if ttl.subsec_nanos() != 0 || ttl < Duration::from_secs(1) {
            return Err(ConfigError::InvalidValue {
                field_path: "auth.stored_output_owner_ttl".to_string(),
                reason: "must be whole seconds and at least 1s".to_string(),
            });
        }
    }

    if !auth.enforce.model_policy && auth.enforce.tenants_without_policy.is_some() {
        return Err(ConfigError::InvalidValue {
            field_path: "auth.enforce.tenants_without_policy".to_string(),
            reason: "has no effect with `model_policy: false`, which omits the filter that \
                     reads it; remove one of the two"
                .to_string(),
        });
    }

    let mut typed_config = json!({
        "@type": AUTH_FILTER_TYPE_URL,
        "hmac_secret": hmac_secret,
        "virtual_keys": virtual_keys,
    });
    // Absent when `auth.jwt` is empty, so configs without it lower
    // byte-identically.
    if !jwt_providers.is_empty() {
        typed_config["jwt_providers"] = json!(jwt_providers);
    }
    // Same rule: absent adds no field.
    if let Some(tags) = &auth.chargeback_tags {
        typed_config["chargeback_tags"] = chargeback::lower_policy(tags)?;
    }
    // Only an explicit `store:` adds a member. Absent means no store field at
    // all, which is what keeps configs written before this field lowering
    // byte-identical.
    if let Some(SimpleDuration(bound)) = auth.max_policy_staleness {
        typed_config["max_policy_staleness_seconds"] = json!(bound.as_secs());
    }
    let store_member = lower_auth_store(auth.store.as_ref())?;
    let store_is_durable = matches!(&store_member, Some(("persistent" | "shared", _)));
    if let Some((member, value)) = store_member {
        typed_config[member] = value;
    }
    // Same rule as `store`: absent adds no field, so configs written before
    // this block existed lower byte-identically. The ring is lowered first so
    // its own field errors win over the store requirement below.
    if let Some(ring) = &auth.tenant_credentials {
        let lowered = lower_tenant_credentials(ring)?;
        // Tenant credentials are sealed rows in the control-plane store. Only
        // `persistent` and `shared` keep them across restarts; `in_memory`
        // loses them (ADR-0007 decision 2). Refused at load, so tenants never
        // fall back to the operator key silently.
        if !store_is_durable {
            return Err(ConfigError::InvalidValue {
                field_path: "auth.tenant_credentials".to_string(),
                reason: TENANT_CREDENTIALS_NEED_DURABLE_STORE.to_string(),
            });
        }
        typed_config["tenant_credentials"] = lowered;
    }

    Ok(Some(json!({
        "name": AUTH_FILTER_NAME,
        "typed_config": typed_config,
    })))
}

/// `auth.store` -> the `llmproxy.filters.v0.Authentication` oneof member that
/// selects it, as `(member name, member value)`. The members are direct
/// fields of `typed_config` (`in_memory`, `persistent`, `shared`), not a
/// nested `store` object, because that is how the proto declares the oneof.
///
/// Same validation shape as `hmac_secret`/`hmac_secret_file` above: every
/// error names the dialect path, and a file-backed Redis URL is read here
/// once so an unreadable file fails at load time rather than at bind time.
/// The URL's contents are never echoed in an error or a warning.
fn lower_auth_store(
    store: Option<&AuthStore>,
) -> Result<Option<(&'static str, Value)>, ConfigError> {
    let Some(store) = store else {
        return Ok(None);
    };
    // Rust note: matching on a tuple of the three `Option`s makes "exactly one
    // set" a single `_` arm, instead of three separate checks that could drift.
    match (&store.in_memory, &store.persistent, &store.shared) {
        (Some(_), None, None) => Ok(Some(("in_memory", json!({})))),
        (None, Some(persistent), None) => {
            if persistent.path.is_empty() {
                return Err(ConfigError::InvalidValue {
                    field_path: "auth.store.persistent.path".to_string(),
                    reason: "must not be empty (an empty path would silently lose every key \
                             minted at runtime)"
                        .to_string(),
                });
            }
            Ok(Some(("persistent", json!({ "path": persistent.path }))))
        }
        (None, None, Some(shared)) => {
            let url = match (&shared.url, &shared.url_file) {
                (Some(url), None) => {
                    if url.is_empty() {
                        return Err(ConfigError::InvalidValue {
                            field_path: "auth.store.shared.url".to_string(),
                            reason: "must not be empty".to_string(),
                        });
                    }
                    json!({ "inline_string": url })
                }
                (None, Some(file)) => {
                    check_readable_non_empty_file(file, "auth.store.shared.url_file")?;
                    json!({ "filename": file })
                }
                (None, None) => {
                    return Err(ConfigError::InvalidValue {
                        field_path: "auth.store.shared".to_string(),
                        reason: "set either url or url_file".to_string(),
                    });
                }
                (Some(_), Some(_)) => {
                    return Err(ConfigError::InvalidValue {
                        field_path: "auth.store.shared".to_string(),
                        reason: "set either url or url_file, not both".to_string(),
                    });
                }
            };
            let mut member = json!({ "url": url });
            if let Some(namespace) = &shared.namespace {
                member["namespace"] = json!(namespace);
            }
            Ok(Some(("shared", member)))
        }
        _ => Err(ConfigError::InvalidValue {
            field_path: "auth.store".to_string(),
            reason: "set exactly one of in_memory, persistent, or shared".to_string(),
        }),
    }
}

/// Refuses `auth.store.shared` when this replica has no configured node id
/// (ADR-0006 addendum "Admission stays local" §5). The dialect has no node id
/// field, so `--service-node` is the only source; the caller passes its
/// value. Lowering cannot check this itself: the node id is a CLI input, not
/// part of the config. The Envoy-mode check in `proxy-filters`' `auth_filter`
/// is the backstop and reports `typed_config.store.shared`.
pub fn require_node_id_for_shared_store(
    config: &SimpleConfig,
    service_node: Option<&str>,
) -> Result<(), ConfigError> {
    let shared = config
        .auth
        .as_ref()
        .and_then(|auth| auth.store.as_ref())
        .is_some_and(|store| store.shared.is_some());
    let configured = service_node.is_some_and(|id| !id.is_empty() && id != "-");
    if shared && !configured {
        return Err(ConfigError::InvalidValue {
            field_path: "auth.store.shared".to_string(),
            reason: SHARED_STORE_NEEDS_NODE_ID.to_string(),
        });
    }
    Ok(())
}

/// Why `auth.store.shared` needs `--service-node`. Without it each boot
/// writes under a fresh per-boot id and the shared store keeps that boot's
/// dedup state.
const SHARED_STORE_NEEDS_NODE_ID: &str = "a shared store requires a configured node id: pass \
     --service-node <name> with a name unique to this replica and stable across its restarts \
     (the dialect has no node id field)";

/// Why `auth.tenant_credentials` needs `auth.store.persistent` or `shared`. The same words
/// as the Envoy-mode check in `proxy-filters`' `auth_filter`, so both entry
/// points report one message.
const TENANT_CREDENTIALS_NEED_DURABLE_STORE: &str = "tenant credentials require a durable store (`persistent` or `shared`): in_memory loses them on restart";

/// `auth.tenant_credentials` -> `llmproxy.filters.v0.TenantCredentials`,
/// lowered verbatim. Only presence and non-emptiness are checked here. Key
/// file contents, permissions, and size are checked by the auth filter when
/// it opens the ring, and the key bytes are never read or echoed by this
/// function.
fn lower_tenant_credentials(ring: &TenantCredentials) -> Result<Value, ConfigError> {
    let encryption_key_file = required_non_empty(
        ring.encryption_key_file.as_deref(),
        "auth.tenant_credentials.encryption_key_file",
    )?;
    let encryption_key_id = required_non_empty(
        ring.encryption_key_id.as_deref(),
        "auth.tenant_credentials.encryption_key_id",
    )?;
    let mut previous_keys = Vec::with_capacity(ring.previous_keys.len());
    for (i, key) in ring.previous_keys.iter().enumerate() {
        let id = required_non_empty(
            key.id.as_deref(),
            &format!("auth.tenant_credentials.previous_keys[{i}].id"),
        )?;
        let file = required_non_empty(
            key.file.as_deref(),
            &format!("auth.tenant_credentials.previous_keys[{i}].file"),
        )?;
        previous_keys.push(json!({ "id": id, "file": file }));
    }
    Ok(json!({
        "encryption_key_file": encryption_key_file,
        "encryption_key_id": encryption_key_id,
        "previous_keys": previous_keys,
    }))
}

/// A required string field: absent and empty are both errors, named at
/// `field_path`.
fn required_non_empty(value: Option<&str>, field_path: &str) -> Result<String, ConfigError> {
    match value {
        None => Err(ConfigError::InvalidValue {
            field_path: field_path.to_string(),
            reason: "is required".to_string(),
        }),
        Some("") => Err(ConfigError::InvalidValue {
            field_path: field_path.to_string(),
            reason: "must not be empty".to_string(),
        }),
        Some(value) => Ok(value.to_string()),
    }
}

/// Reads `file` once purely to check it is readable and non-empty. The
/// contents are discarded, never echoed, and never folded into the lowered
/// config, which keeps `filename` so the proxy reads the URL again itself.
fn check_readable_non_empty_file(file: &str, field_path: &str) -> Result<(), ConfigError> {
    let contents = std::fs::read_to_string(file).map_err(|e| ConfigError::Io {
        path: file.to_string(),
        reason: e.to_string(),
    })?;
    if contents.trim_end_matches(['\n', '\r']).is_empty() {
        return Err(ConfigError::InvalidValue {
            field_path: field_path.to_string(),
            reason: "must not be empty".to_string(),
        });
    }
    Ok(())
}

// ------------------------------------------------------------------ limits --

/// `limits` -> one `llmproxy.token_limit` `http_filters` entry carrying one
/// `rules[]` element per `limits[i]`, in order.
///
/// Every `limits` field is enforced as written (AGENTS.md invariant 1), so no
/// warning is emitted from here. Rule buckets are route-independent, windows
/// are one epoch-aligned minute, and a request must pass every rule that
/// applies to it; the filter owns those semantics, this function only
/// translates fields.
///
/// Behavior note: `key: header:authorization` counts each credential apart.
/// Behind `auth:` the filter buckets on the authenticated key id, since
/// `llmproxy.auth` removes the verified header. It used to switch to the
/// authenticated tenant silently; write `key: tenant` for that.
fn lower_limits(config: &SimpleConfig) -> Result<Option<Value>, ConfigError> {
    let mut rules: Vec<Value> = Vec::with_capacity(config.limits.len());

    for (i, limit) in config.limits.iter().enumerate() {
        let path = format!("limits[{i}]");

        // `key: tenant` needs an `auth:` block to mean anything -- without
        // one, nothing authenticates a tenant, so the bucket would have no
        // identity to count against. AGENTS.md invariant 1: a hard error,
        // not a warning -- this is a config that lies about what it enforces.
        if matches!(&limit.key, LimitKey::Tenant) && config.auth.is_none() {
            return Err(ConfigError::InvalidValue {
                field_path: format!("{path}.key"),
                reason: "`key: tenant` requires an `auth:` block; with none configured, \
                         nothing would authenticate a tenant -- add `auth:`, or use a \
                         different key"
                    .to_string(),
            });
        }

        // Rust note: `serde_json::Map` keeps this rule's JSON object mutable
        // so absent optional fields can simply be skipped.
        let mut rule = serde_json::Map::new();
        match &limit.key {
            LimitKey::Global => {
                rule.insert("key".into(), json!("GLOBAL"));
            }
            LimitKey::ClientIp => {
                rule.insert("key".into(), json!("CLIENT_IP"));
            }
            LimitKey::Tenant => {
                rule.insert("key".into(), json!("TENANT"));
            }
            LimitKey::Header(name) => {
                rule.insert("key".into(), json!("HEADER"));
                // HTTP header names are case-insensitive; the filter looks
                // them up lowercased.
                rule.insert("header".into(), json!(name.to_ascii_lowercase()));
            }
        }
        if let Some(tokens) = limit.tokens_per_minute {
            rule.insert("tokens_per_minute".into(), json!(tokens.0));
        }
        if let Some(requests) = limit.requests_per_minute {
            rule.insert("requests_per_minute".into(), json!(requests.0));
        }
        if let Some(sessions) = limit.concurrent_sessions {
            // `concurrent_sessions` counts streams in flight.
            let streams = u32::try_from(sessions).map_err(|_| ConfigError::InvalidValue {
                field_path: format!("{path}.concurrent_sessions"),
                reason: format!("`{sessions}` exceeds the maximum ({})", u32::MAX),
            })?;
            rule.insert("concurrent_streams".into(), json!(streams));
        }
        if !limit.models.is_empty() {
            for (j, model) in limit.models.iter().enumerate() {
                if !is_valid_limit_model_pattern(model) {
                    return Err(ConfigError::InvalidValue {
                        field_path: format!("{path}.models[{j}]"),
                        reason: format!(
                            "`{model}` must be an exact model name or a single trailing `*`"
                        ),
                    });
                }
            }
            rule.insert("models".into(), json!(limit.models));
        }
        rules.push(Value::Object(rule));
    }

    if rules.is_empty() {
        return Ok(None);
    }
    Ok(Some(json!({
        "name": TOKEN_LIMIT_FILTER_NAME,
        "typed_config": {
            "@type": TOKEN_LIMIT_FILTER_TYPE_URL,
            "rules": rules,
        }
    })))
}

/// An exact model name, or a name with a single trailing `*`. Mirrors
/// `proxy_control::model_authz::ModelPattern::is_valid`, which this crate
/// cannot call (`proxy-filters` is a dev-dependency only).
fn is_valid_limit_model_pattern(pattern: &str) -> bool {
    !pattern.is_empty()
        && (!pattern.contains('*') || (pattern.matches('*').count() == 1 && pattern.ends_with('*')))
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
        LogFormat::Json => {
            let mut format = json!({
                "start_time": "%START_TIME%",
                "method": "%REQ(:METHOD)%",
                "path": "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%",
                "protocol": "%PROTOCOL%",
                "response_code": "%RESPONSE_CODE%",
                "response_flags": "%RESPONSE_FLAGS%",
                "response_code_details": "%RESPONSE_CODE_DETAILS%",
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
                "llm_resolved_model": "%LLM_RESOLVED_MODEL%",
                "llm_guardrail": "%LLM_GUARDRAIL%",
                "llm_selected_model": "%LLM_SELECTED_MODEL%",
                "llm_rate_card_version": "%LLM_RATE_CARD_VERSION%",
                "selected_provider": "%UPSTREAM_CLUSTER%",
                "llm_list_cost_nanodollars": "%LLM_LIST_COST%",
                "llm_credential_source": "%LLM_CREDENTIAL_SOURCE%",
                "llm_served_model": "%LLM_SERVED_MODEL%",
                "llm_usage_completeness": "%LLM_USAGE_COMPLETENESS%",
                "llm_cost_kind": "%LLM_COST_KIND%",
                "llm_upstream_id": "%LLM_UPSTREAM_ID%",
                // Embedded as a JSON value, not a string; it has no text-format
                // twin because raw JSON would break that line's quoting.
                "llm_upstream_usage": "%LLM_UPSTREAM_USAGE%",
            });
            // Added in a loop: one more `json!` entry hits the macro's
            // recursion limit.
            for (key, operator) in MEDIA_FIELDS {
                format[key] = json!(operator);
            }
            for (phase, operator) in TIMING_PHASES {
                format[format!("{phase}_us")] = json!(operator);
            }
            json!({ "json_format": format })
        }
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

// ------------------------------------------------------------------ ledger --

/// Must equal `proxy_config`'s `LEDGER_METADATA_KEY`; `tests/ledger.rs`
/// round-trips the dialect through the real Envoy-mode loader, so a drift
/// here shows up as a ledger that never reaches the snapshot.
const LEDGER_METADATA_KEY: &str = "io.llmproxy.ledger";

/// `ledger` -> `Bootstrap.node.metadata["io.llmproxy.ledger"]`. Required
/// fields are checked here so a missing one is reported at `ledger.<field>`;
/// unset optional fields are left out, so the Envoy-mode reader's defaults
/// apply to both modes. Ranges are that reader's to enforce, the same split
/// as `lower_metrics`. Durations go over as seconds numbers.
fn lower_ledger(ledger: &crate::model::Ledger) -> Result<Value, ConfigError> {
    let mut out = serde_json::Map::new();
    out.insert(
        "directory".into(),
        json!(required_non_empty(
            ledger.directory.as_deref(),
            "ledger.directory"
        )?),
    );
    out.insert(
        "encryption_key_file".into(),
        json!(required_non_empty(
            ledger.encryption_key_file.as_deref(),
            "ledger.encryption_key_file"
        )?),
    );
    out.insert(
        "encryption_key_id".into(),
        json!(required_non_empty(
            ledger.encryption_key_id.as_deref(),
            "ledger.encryption_key_id"
        )?),
    );
    let max_disk_bytes = ledger
        .max_disk_bytes
        .ok_or_else(|| ConfigError::InvalidValue {
            field_path: "ledger.max_disk_bytes".to_string(),
            reason: "is required".to_string(),
        })?;
    out.insert("max_disk_bytes".into(), json!(max_disk_bytes));
    if !ledger.previous_keys.is_empty() {
        let mut keys = Vec::with_capacity(ledger.previous_keys.len());
        for (i, key) in ledger.previous_keys.iter().enumerate() {
            keys.push(json!({
                "id": required_non_empty(key.id.as_deref(), &format!("ledger.previous_keys[{i}].id"))?,
                "file": required_non_empty(key.file.as_deref(), &format!("ledger.previous_keys[{i}].file"))?,
            }));
        }
        out.insert("previous_keys".into(), Value::Array(keys));
    }
    if let Some(n) = ledger.max_reservations {
        out.insert("max_reservations".into(), json!(n));
    }
    if let Some(n) = ledger.group_commit_max_entries {
        out.insert("group_commit_max_entries".into(), json!(n));
    }
    if let Some(interval) = ledger.group_commit_interval {
        out.insert(
            "group_commit_interval".into(),
            json!(interval.0.as_secs_f64()),
        );
    }
    if let Some(mode) = ledger.on_unavailable {
        let mode = match mode {
            crate::model::LedgerOnUnavailable::Reject => "reject",
            crate::model::LedgerOnUnavailable::Admit => "admit",
        };
        out.insert("on_unavailable".into(), json!(mode));
    }
    Ok(Value::Object(out))
}

// ------------------------------------------------------------------ traces --

/// Must equal `proxy_config`'s `TRACES_METADATA_KEY`; `tests/traces.rs`
/// round-trips the dialect through the real Envoy-mode loader, so a drift
/// here shows up as a trace block that never reaches the snapshot.
const TRACES_METADATA_KEY: &str = "io.llmproxy.traces";

/// `observability.traces` -> `Bootstrap.node.metadata["io.llmproxy.traces"]`.
/// Required fields are checked here so a missing one is reported at
/// `observability.traces.<field>`; unset optional fields are left out, so the
/// Envoy-mode reader's defaults apply to both modes. Ranges and cross-field
/// rules are that reader's to enforce, the same split as `lower_ledger`.
/// Durations go over as seconds numbers.
fn lower_traces(traces: &crate::model::Traces) -> Result<Value, ConfigError> {
    const ROOT: &str = "observability.traces";
    let mut out = serde_json::Map::new();
    out.insert(
        "directory".into(),
        json!(required_non_empty(
            traces.directory.as_deref(),
            "observability.traces.directory"
        )?),
    );
    let max_disk_bytes = traces
        .max_disk_bytes
        .ok_or_else(|| ConfigError::InvalidValue {
            field_path: format!("{ROOT}.max_disk_bytes"),
            reason: "is required".to_string(),
        })?;
    out.insert("max_disk_bytes".into(), json!(max_disk_bytes));
    if let Some(age) = traces.max_age {
        out.insert("max_age".into(), json!(age.0.as_secs_f64()));
    }
    if let Some(codec) = traces.codec {
        let codec = match codec {
            crate::model::TraceCodec::Gzip => "gzip",
            crate::model::TraceCodec::Zstd => "zstd",
        };
        out.insert("codec".into(), json!(codec));
    }
    for (key, value) in [
        ("zstd_window_log", traces.zstd_window_log),
        ("max_request_body_bytes", traces.max_request_body_bytes),
        ("max_response_body_bytes", traces.max_response_body_bytes),
        ("max_memory_bytes", traces.max_memory_bytes),
        ("max_queued_traces", traces.max_queued_traces),
        ("segment_max_bytes", traces.segment_max_bytes),
        ("max_open_segments", traces.max_open_segments),
    ] {
        if let Some(n) = value {
            out.insert(key.into(), json!(n));
        }
    }
    if let Some(age) = traces.segment_max_age {
        out.insert("segment_max_age".into(), json!(age.0.as_secs_f64()));
    }
    if let Some(s3) = &traces.s3 {
        const S3_ROOT: &str = "observability.traces.s3";
        let mut dest = serde_json::Map::new();
        for (key, value) in [
            ("bucket", s3.bucket.as_deref()),
            ("region", s3.region.as_deref()),
            ("access_key_id", s3.access_key_id.as_deref()),
            ("secret_access_key", s3.secret_access_key.as_deref()),
        ] {
            dest.insert(
                key.into(),
                json!(required_non_empty(value, &format!("{S3_ROOT}.{key}"))?),
            );
        }
        for (key, value) in [
            ("endpoint", s3.endpoint.as_deref()),
            ("prefix", s3.prefix.as_deref()),
            ("session_token", s3.session_token.as_deref()),
        ] {
            if let Some(v) = value {
                dest.insert(key.into(), json!(v));
            }
        }
        if let Some(b) = s3.path_style {
            dest.insert("path_style".into(), json!(b));
        }
        if let Some(t) = s3.upload_timeout {
            dest.insert("upload_timeout".into(), json!(t.0.as_secs_f64()));
        }
        out.insert("s3".into(), Value::Object(dest));
    }
    Ok(Value::Object(out))
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
    let (address, tls, max_request_body_bytes) = match &config.listen {
        None => (("0.0.0.0".to_string(), 8080), None, None),
        Some(Listen::Address(a)) => (parse_host_port(a, "listen")?, None, None),
        Some(Listen::Full(spec)) => (
            parse_host_port(&spec.address, "listen.address")?,
            spec.tls.as_ref(),
            spec.max_request_body_bytes,
        ),
    };
    let (headers_timeout, request_timeout) = request_timeouts(config);
    let (stream_idle_timeout, max_stream_duration) = stream_timeouts(config);

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
        // FIRST, ahead of everything else added to the chain below -- see
        // `AUTH_FILTER_NAME`'s doc for why (an unauthenticated request must
        // be refused before the body-peek filter parses it, and the token
        // limiter must see `StreamInfo::auth.tenant` already written).
        http_filters.push(auth_filter);
    }
    if enforces_object_ownership(config) {
        // After auth (reads the tenant and its control-plane store); before
        // anything that reads the body, so a refused request is not parsed.
        let owner_ttl = config
            .auth
            .as_ref()
            .and_then(|auth| auth.stored_output_owner_ttl)
            .map_or(
                Duration::from_secs(DEFAULT_STORED_OUTPUT_OWNER_TTL_SECS),
                |SimpleDuration(ttl)| ttl,
            );
        http_filters.push(json!({
            "name": "llmproxy.object_ownership",
            "typed_config": object_ownership_config(owner_ttl),
        }));
    }
    if needs_body_rewrite_filter(config) {
        // Decode-path filter, so it must precede the router in config order --
        // decode callbacks run in FORWARD config order (S2.1), and a decode
        // filter placed after the router never runs at all. `enabled` here
        // gates ONLY consumer A (the `include_usage` splice): a config with
        // `routes`/`models` but `force_usage_reporting: false` still needs
        // this filter present, just with the splice off.
        http_filters.push(json!({
            "name": BODY_REWRITE_FILTER_NAME,
            "typed_config": body_rewrite_typed_config(force_usage_reporting(config), default_dialect, None),
        }));
    }
    if let Some(auto) = &config.auto {
        // After `llmproxy.auth` and `llmproxy.body_rewrite` (it reads the
        // tenant and the extracted model); `check_lane_h_filter_order`
        // rejects any other order.
        http_filters.push(json!({
            "name": MODEL_RESOLVER_FILTER_NAME,
            "typed_config": model_resolver_typed_config(auto),
        }));
    }
    if enforces_model_policy(config) {
        // After auth (reads `StreamInfo::auth.tenant`), body_rewrite (publishes
        // the requested model) and the resolver when present (publishes the
        // routing model it authorizes); decode runs in config order.
        // `policies` stays empty: live policy comes from the admin store. A
        // tenant with no stored policy is refused unless the operator set
        // `auth.enforce.tenants_without_policy: allow`; the default adds no
        // field, which the proto reads as DENY.
        let mut typed_config = json!({ "@type": MODEL_AUTHZ_FILTER_TYPE_URL });
        if allows_tenants_without_policy(config) {
            typed_config["tenants_without_policy"] = json!("ALLOW");
        }
        // The filter answers `GET /v1/models` with the subset of this
        // catalogue the caller's tenant grant and key policy permit.
        let catalog = model_catalog(config);
        if !catalog.is_empty() {
            typed_config["model_catalog"] = json!(catalog);
        }
        http_filters.push(json!({
            "name": "llmproxy.model_authz",
            "typed_config": typed_config,
        }));
    }
    if let Some(guardrails) = &config.guardrails {
        // After auth, body_rewrite, the resolver and model_authz (only an
        // authorized request is disclosed to a check, with its resolved
        // model); before the limiters and usage, so a denied request is never
        // counted or charged. `check_lane_h_filter_order` rejects any other
        // order.
        http_filters.push(json!({
            "name": GUARDRAIL_FILTER_NAME,
            "typed_config": guardrail_typed_config(guardrails),
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
    if enforces_spend(config) {
        // After auth (tenant) and before usage, whose encode callback runs
        // first and reports the cost this filter records. Prices come from the
        // usage filter's rate card, so no `pricing` list is repeated here.
        // START_KEYS_FRESH is unconditional: the dialect never had legacy
        // tenant budgets, so there is no history to cut over from, and without
        // it a stored tenant budget would block the next start.
        http_filters.push(json!({
            "name": "llmproxy.spend_limit",
            "typed_config": {
                "@type": SPEND_LIMIT_FILTER_TYPE_URL,
                "legacy_tenant_budget_cutover": "START_KEYS_FRESH",
            },
        }));
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
    // Always emitted: the dialect ships safe defaults, and `0s` is how an
    // operator disables one (Envoy reads `0s` as disabled).
    hcm["typed_config"]["request_headers_timeout"] = json!(headers_timeout.to_string());
    hcm["typed_config"]["request_timeout"] = json!(request_timeout.to_string());
    // `stream_idle_timeout` is always emitted for the same reason: unset would
    // fall back to Envoy's own 5 minute default, not to the dialect's.
    hcm["typed_config"]["stream_idle_timeout"] = json!(stream_idle_timeout.to_string());
    if let Some(max) = max_stream_duration {
        hcm["typed_config"]["common_http_protocol_options"]["max_stream_duration"] =
            json!(max.to_string());
    }
    // Unset is left out, so Envoy's own defaults (60 KiB, 100) apply.
    let spec = listener_spec(config);
    if let Some(kb) = spec.and_then(|s| s.max_request_headers_kb) {
        hcm["typed_config"]["max_request_headers_kb"] = json!(kb);
    }
    if let Some(count) = spec.and_then(|s| s.max_request_headers_count) {
        hcm["typed_config"]["common_http_protocol_options"]["max_headers_count"] = json!(count);
    }
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

    let mut listener = json!({
        "name": "llmproxy_listener",
        "address": { "socket_address": {
            "address": address.0, "port_value": address.1
        } },
        "filter_chains": [filter_chain],
    });
    if let Some(limit) = max_request_body_bytes {
        listener["per_connection_buffer_limit_bytes"] = json!(limit);
    }
    Ok(listener)
}

/// The listener spec when `listen` is the object form (the only form that can
/// carry overrides); the shorthand string and an absent `listen` use defaults.
fn listener_spec(config: &SimpleConfig) -> Option<&crate::model::ListenerSpec> {
    match &config.listen {
        Some(Listen::Full(spec)) => Some(spec),
        _ => None,
    }
}

/// (request_headers_timeout, request_timeout) with the dialect's defaults.
fn request_timeouts(config: &SimpleConfig) -> (SimpleDuration, SimpleDuration) {
    let spec = listener_spec(config);
    (
        spec.and_then(|s| s.request_headers_timeout)
            .unwrap_or(SimpleDuration(
                crate::model::DEFAULT_REQUEST_HEADERS_TIMEOUT,
            )),
        spec.and_then(|s| s.request_timeout)
            .unwrap_or(SimpleDuration(crate::model::DEFAULT_REQUEST_TIMEOUT)),
    )
}

/// (stream_idle_timeout, max_stream_duration). The second is `None` unless the
/// operator sets it; `0s` also means no limit.
fn stream_timeouts(config: &SimpleConfig) -> (SimpleDuration, Option<SimpleDuration>) {
    let spec = listener_spec(config);
    (
        spec.and_then(|s| s.stream_idle_timeout)
            .unwrap_or(SimpleDuration(crate::model::DEFAULT_STREAM_IDLE_TIMEOUT)),
        spec.and_then(|s| s.max_stream_duration)
            .filter(|d| !d.0.is_zero()),
    )
}

fn max_connections(config: &SimpleConfig) -> u64 {
    listener_spec(config)
        .and_then(|s| s.max_connections)
        .unwrap_or(crate::model::DEFAULT_MAX_CONNECTIONS)
}

fn warning(field_path: impl Into<String>, message: impl Into<String>) -> ConfigWarning {
    ConfigWarning {
        field_path: field_path.into(),
        message: message.into(),
    }
}
