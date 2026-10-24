//! The dialect data model — a 1:1 mirror of `schema/llmproxy-v1.schema.json`.
//!
//! The schema is normative; strict deserialization rejects undefined fields.
//! Constrained scalar shapes parse eagerly so errors retain their field paths.
//! Providers describe endpoint instances, while models map client names to ordered
//! provider choices. Ambiguous dialects must be explicit to avoid missed usage
//! accounting; catalogue keys follow Envoy domain precedence (S1).

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

mod jwt;
pub use jwt::*;

/// The schema version this build writes in examples and expects: `version: 1`.
/// It freezes the shape of the v0 dialect for the 1.x releases.
pub const SCHEMA_VERSION: u64 = 1;

/// The schema version before 1.0. It has the same shape as version 1, so it
/// still loads in 1.x, with a deprecation warning at `version`.
pub const DEPRECATED_SCHEMA_VERSION: u64 = 0;

/// Top-level keys reserved for future schema versions; rejected today so they
/// can be added compatibly later.
pub const RESERVED_KEYS: &[&str] = &["envoy", "tracing", "clusters"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimpleConfig {
    /// [`SCHEMA_VERSION`], or the deprecated [`DEPRECATED_SCHEMA_VERSION`]
    /// (checked in semantic validation for a friendlier error).
    pub version: u64,
    #[serde(default)]
    pub listen: Option<Listen>,
    #[serde(default)]
    pub admin: Option<Admin>,
    /// Downstream authentication. Absent means the
    /// proxy admits every request unauthenticated, same as today. Present,
    /// even with `keys: []`, switches the listener to fail-closed.
    #[serde(default)]
    pub auth: Option<Auth>,
    /// Rust note: `BTreeMap` (not `HashMap`) keeps providers sorted by name,
    /// making the lowered Envoy config deterministic — same input, same output.
    pub providers: BTreeMap<String, Provider>,
    /// Client-facing names mapped to ordered provider choices. Each gets an
    /// implicit route in addition to explicit `routes`; duplicate keys are
    /// rejected by `deserialize_model_catalog`.
    #[serde(default, deserialize_with = "deserialize_model_catalog")]
    pub models: BTreeMap<String, ModelDef>,
    pub routes: Vec<RouteRule>,
    #[serde(default)]
    pub limits: Vec<Limit>,
    #[serde(default)]
    pub observability: Option<Observability>,
    /// Versioned provider model rate card. The list is read once at startup;
    /// replacing it requires a config reload.
    #[serde(default)]
    pub pricing: Option<Pricing>,
    /// Resolution of the reserved model name `auto`. Absent means `auto` is
    /// an ordinary model name.
    #[serde(default)]
    pub auto: Option<AutoModel>,
    /// The billing ledger (ADR-0009): one durable, encrypted entry per
    /// dialled request. Absent means no ledger.
    #[serde(default)]
    pub ledger: Option<Ledger>,
    /// Body-aware request checks. Absent means no request is checked.
    #[serde(default)]
    pub guardrails: Option<Guardrails>,
    /// Realtime (WebSocket) sessions. Absent means every upgrade is refused.
    #[serde(default)]
    pub realtime: Option<Realtime>,
}

/// `realtime`: lowers to the listener HCM's
/// `upgrade_configs: [{upgrade_type: websocket}]` (envoy-semantics.md S10).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Realtime {
    pub enabled: bool,
}

/// `guardrails`: which check each request's body is sent to. Lowers to the
/// `llmproxy.guardrail` filter. Required fields are `Option`s so a missing one
/// is reported at its own path, as for [`Ledger`].
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Guardrails {
    /// The check for a tenant with no entry in `tenants`, and for a request
    /// with no authenticated tenant. Required.
    #[serde(default)]
    pub default: Option<GuardrailCheck>,
    /// Tenant -> check, replacing `default`. `deserialize_with` rejects a
    /// duplicate tenant rather than keeping the last one.
    #[serde(default, deserialize_with = "deserialize_guardrail_tenants")]
    pub tenants: BTreeMap<String, GuardrailCheck>,
}

/// One check: exactly one backend (only `http` today) and its failure mode.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardrailCheck {
    #[serde(default)]
    pub http: Option<HttpGuardrail>,
    #[serde(default)]
    pub failure_mode: Option<GuardrailFailureMode>,
}

/// What a check does when it cannot decide. No default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailFailureMode {
    Closed,
    Open,
}

/// An external HTTP check.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpGuardrail {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub timeout: Option<SimpleDuration>,
    #[serde(default)]
    pub max_body_bytes: Option<u64>,
}

/// Deserializes `guardrails.tenants`, erroring on a literal duplicate tenant,
/// for the same reason as [`deserialize_model_catalog`].
fn deserialize_guardrail_tenants<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, GuardrailCheck>, D::Error>
where
    D: Deserializer<'de>,
{
    struct GuardrailTenantsVisitor;

    impl<'de> Visitor<'de> for GuardrailTenantsVisitor {
        type Value = BTreeMap<String, GuardrailCheck>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a map of tenant -> check")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut out = BTreeMap::new();
            while let Some(key) = map.next_key::<String>()? {
                if out.contains_key(&key) {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate `guardrails.tenants` entry `{key}`"
                    )));
                }
                let value = map.next_value::<GuardrailCheck>()?;
                out.insert(key, value);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_map(GuardrailTenantsVisitor)
}

/// `ledger`: lowers to `node.metadata["io.llmproxy.ledger"]`, which owns the
/// defaults and range checks. Required fields are `Option`s so a missing one
/// is reported at `ledger.<field>` rather than as serde's missing field on
/// the enclosing block.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ledger {
    #[serde(default)]
    pub directory: Option<String>,
    #[serde(default)]
    pub encryption_key_file: Option<String>,
    #[serde(default)]
    pub encryption_key_id: Option<String>,
    #[serde(default)]
    pub previous_keys: Vec<PreviousCredentialKey>,
    #[serde(default)]
    pub max_disk_bytes: Option<u64>,
    #[serde(default)]
    pub max_reservations: Option<u64>,
    #[serde(default)]
    pub group_commit_max_entries: Option<u64>,
    #[serde(default)]
    pub group_commit_interval: Option<SimpleDuration>,
    /// Unset means `reject`.
    #[serde(default)]
    pub on_unavailable: Option<LedgerOnUnavailable>,
}

/// `ledger.on_unavailable`: what admission does with no ledger slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerOnUnavailable {
    /// A local 503; nothing reaches a provider unledgered.
    Reject,
    /// Serve without an entry; counted and warned (fail-open).
    Admit,
}

/// `auto`: which model a request for `auto` gets. Lowers to the
/// `llmproxy.model_resolver` filter's in-process rules.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutoModel {
    /// The model for a tenant with no entry in `tenants`, and for a request
    /// with no authenticated tenant. Absent means such a request is refused.
    #[serde(default)]
    pub default: Option<String>,
    /// Tenant -> model. `deserialize_with` rejects a duplicate tenant rather
    /// than keeping the last one.
    #[serde(default, deserialize_with = "deserialize_auto_tenants")]
    pub tenants: BTreeMap<String, String>,
}

/// Deserializes `auto.tenants`, erroring on a literal duplicate tenant, for
/// the same reason as [`deserialize_model_catalog`].
fn deserialize_auto_tenants<'de, D>(deserializer: D) -> Result<BTreeMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct AutoTenantsVisitor;

    impl<'de> Visitor<'de> for AutoTenantsVisitor {
        type Value = BTreeMap<String, String>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a map of tenant -> model")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut out = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, String>()? {
                if out.insert(key.clone(), value).is_some() {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate `auto.tenants` entry `{key}`"
                    )));
                }
            }
            Ok(out)
        }
    }

    deserializer.deserialize_map(AutoTenantsVisitor)
}

/// Reject duplicate model keys instead of silently keeping the last value.
/// Rust note: a custom visitor sees each map entry before serde can overwrite it.
fn deserialize_model_catalog<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, ModelDef>, D::Error>
where
    D: Deserializer<'de>,
{
    struct ModelCatalogVisitor;

    impl<'de> Visitor<'de> for ModelCatalogVisitor {
        type Value = BTreeMap<String, ModelDef>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a map of model name -> model definition")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut out = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, ModelDef>()? {
                if out.insert(key.clone(), value).is_some() {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate `models` entry `{key}` -- each catalogue key must be \
                         unique, and precedence between two identical patterns is never \
                         resolved silently"
                    )));
                }
            }
            Ok(out)
        }
    }

    deserializer.deserialize_map(ModelCatalogVisitor)
}

/// `listen`: shorthand `host:port` string, or an object to enable TLS.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Listen {
    Address(String),
    Full(ListenerSpec),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerSpec {
    pub address: String,
    #[serde(default)]
    pub tls: Option<ListenTls>,
    /// The largest request body the listener accepts, in bytes. Lowers to the
    /// listener's `per_connection_buffer_limit_bytes`; unset keeps its 1 MiB
    /// default. A larger body gets `413`.
    #[serde(default)]
    pub max_request_body_bytes: Option<u32>,
    /// Cap on simultaneously open client connections for the whole proxy.
    /// Unset means [`DEFAULT_MAX_CONNECTIONS`]; must be greater than 0.
    #[serde(default)]
    pub max_connections: Option<u64>,
    /// Time allowed from a request's first byte to its complete headers.
    /// Unset means 10s; `0s` disables the timeout.
    #[serde(default)]
    pub request_headers_timeout: Option<SimpleDuration>,
    /// Time allowed to receive the complete request (headers and body).
    /// Unset means 60s; `0s` disables the timeout.
    #[serde(default)]
    pub request_timeout: Option<SimpleDuration>,
    /// How long a request may go with no activity before it is cut: the wait
    /// for the provider's response headers, and (on a rule with no
    /// `idle_timeout` of its own) the gap between response chunks. Unset
    /// means 10m; `0s` disables the timeout.
    #[serde(default)]
    pub stream_idle_timeout: Option<SimpleDuration>,
    /// The longest a request may live from receipt to the last response byte,
    /// however active it is. Unset means no limit.
    #[serde(default)]
    pub max_stream_duration: Option<SimpleDuration>,
    /// The largest request head (request line and headers) accepted, in KiB.
    /// Unset means Envoy's 60; must be in 1..=8192. A larger head gets `431`.
    #[serde(default)]
    pub max_request_headers_kb: Option<u32>,
    /// The most headers a request may carry. Unset means Envoy's 100; must be
    /// greater than 0. More gets `431`.
    #[serde(default)]
    pub max_request_headers_count: Option<u32>,
    /// Proxies in front of this one that append to `x-forwarded-for`, such
    /// as a load balancer. Client-ip limits, request records and access logs
    /// then attribute a request to the address the outermost trusted proxy
    /// saw. Unset or 0 means the TCP peer, and `x-forwarded-for` is never
    /// read. Lowers to the HCM's `use_remote_address: true` and
    /// `xff_num_trusted_hops` (envoy-semantics S9). Signed so a negative
    /// value fails validation with this path, not as a mismatch of the whole
    /// untagged `listen`.
    #[serde(default)]
    pub trusted_hops: Option<i64>,
}

/// Safe edge-proxy defaults for the admission limits, from Envoy's edge
/// best-practices guidance. Envoy mode keeps Envoy's own (disabled) defaults.
pub const DEFAULT_MAX_CONNECTIONS: u64 = 50_000;
pub const DEFAULT_REQUEST_HEADERS_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Long enough for a non-streaming generation that sends nothing until it
/// finishes, short enough that a provider which accepts and never answers
/// cannot hold a client and a `max_requests` permit forever.
pub const DEFAULT_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// `admin`: shorthand `host:port` string, or an object to enable TLS. Same
/// shape as [`Listen`].
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Admin {
    Address(String),
    Full(AdminSpec),
}

impl Admin {
    /// The bind address, and the dotted path that names it in errors.
    pub fn address(&self) -> (&str, &'static str) {
        match self {
            Admin::Address(a) => (a, "admin"),
            Admin::Full(spec) => (&spec.address, "admin.address"),
        }
    }

    pub fn tls(&self) -> Option<&ListenTls> {
        match self {
            Admin::Address(_) => None,
            Admin::Full(spec) => spec.tls.as_ref(),
        }
    }
}

/// `admin` object form. `tls` lowers to
/// `node.metadata["io.llmproxy.admin_tls"]`, since Envoy's admin has no TLS
/// of its own.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminSpec {
    pub address: String,
    #[serde(default)]
    pub tls: Option<ListenTls>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenTls {
    pub cert_file: String,
    pub key_file: String,
}

/// `providers.<name>.oauth2_jwt_bearer`. Every value is config; the proxy
/// knows no provider's token URL or scope.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuth2JwtBearerDef {
    /// Token endpoint. `https`, or `http` to a loopback host only.
    pub token_url: String,
    /// JWT `iss`, for example a service account's email address.
    pub issuer: String,
    /// JWT `sub`, when the grant impersonates another principal.
    #[serde(default)]
    pub subject: Option<String>,
    /// JWT header `kid`.
    #[serde(default)]
    pub key_id: Option<String>,
    /// RSA private key, PKCS#8 PEM. Read and checked at every load.
    pub private_key_file: String,
    /// Joined with spaces into the JWT `scope` claim.
    pub scopes: Vec<String>,
    /// JWT `aud`; defaults to `token_url`.
    #[serde(default)]
    pub audience: Option<String>,
    /// `exp - iat` of each assertion. Default 1h.
    #[serde(default)]
    pub assertion_lifetime: Option<SimpleDuration>,
    /// Mint the next token this long before the current one expires.
    /// Default 5m.
    #[serde(default)]
    pub refresh_before: Option<SimpleDuration>,
    /// Bounds one token request. Default 10s.
    #[serde(default)]
    pub timeout: Option<SimpleDuration>,
    /// PEM bundle that verifies an `https` token endpoint instead of the
    /// platform roots.
    #[serde(default)]
    pub ca_file: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    #[serde(default, rename = "type")]
    pub provider_type: Option<ProviderType>,
    #[serde(default)]
    pub base_url: Option<String>,
    /// Google Cloud project used by Vertex AI.
    #[serde(default)]
    pub project: Option<String>,
    /// Google Cloud location used by Vertex AI.
    #[serde(default)]
    pub location: Option<String>,
    /// Vertex publisher, such as `google` or `anthropic`.
    #[serde(default)]
    pub publisher: Option<String>,
    /// OAuth access token used by Vertex AI. Exactly one token source is
    /// required for a Vertex provider.
    #[serde(default)]
    pub access_token: Option<String>,
    /// File containing a Vertex OAuth access token. Exactly one token source
    /// is required for a Vertex provider.
    #[serde(default)]
    pub access_token_file: Option<String>,
    /// Mint and refresh the access token with the OAuth2 JWT-bearer grant
    /// (RFC 7523) instead of configuring one. A Vertex token source, exclusive
    /// with `access_token` and `access_token_file`.
    #[serde(default)]
    pub oauth2_jwt_bearer: Option<OAuth2JwtBearerDef>,
    /// AWS region used by Amazon Bedrock.
    #[serde(default)]
    pub region: Option<String>,
    /// AWS access key ID. Exactly one access-key source is required for a
    /// Bedrock provider.
    #[serde(default)]
    pub access_key_id: Option<String>,
    /// File containing an AWS access key ID. Exactly one access-key source is
    /// required for a Bedrock provider.
    #[serde(default)]
    pub access_key_id_file: Option<String>,
    /// AWS secret access key. Exactly one secret-key source is required for a
    /// Bedrock provider.
    #[serde(default)]
    pub secret_access_key: Option<String>,
    /// File containing an AWS secret access key. Exactly one secret-key source
    /// is required for a Bedrock provider.
    #[serde(default)]
    pub secret_access_key_file: Option<String>,
    /// Optional AWS session token. If configured, exactly one token source is
    /// required.
    #[serde(default)]
    pub session_token: Option<String>,
    /// File containing an optional AWS session token.
    #[serde(default)]
    pub session_token_file: Option<String>,
    /// Azure OpenAI deployment name used in the provider-owned request path.
    #[serde(default)]
    pub deployment: Option<String>,
    /// Azure OpenAI api-version query value.
    #[serde(default)]
    pub api_version: Option<String>,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub api_key_file: Option<String>,
    #[serde(default)]
    pub extra_headers: BTreeMap<String, String>,
    #[serde(default)]
    pub ca_file: Option<String>,
    #[serde(default)]
    pub connect_timeout: Option<SimpleDuration>,
    /// Upstream HTTP protocol for this provider's cluster. `None` means
    /// `http1` (Envoy's own default for an unconfigured cluster), which
    /// keeps every config predating this field byte-identical in behavior.
    #[serde(default)]
    pub protocol: Option<UpstreamProtocol>,
    /// Opts this provider into tenant provider credentials (ADR-0007). Its
    /// cluster then carries a tenant credential slot with the same header the
    /// operator key uses, so a tenant holding a key for this provider sends
    /// that key instead. Requires `auth.tenant_credentials`. Default `false`.
    #[serde(default)]
    pub tenant_credentials: bool,
    /// Upstream path of the zero-cost `GET` that checks a tenant key when it is
    /// saved (ADR-0007 decision 10), e.g. `/api/v1/key`. Requires
    /// `tenant_credentials: true`. Unset defaults to `/api/v1/key` for
    /// `openrouter`, `/v1/models` for `openai` and `anthropic`, and nothing for
    /// other types. Nothing is defaulted when `base_url` is set. The path is
    /// sent as is, without the cluster path rewrite.
    #[serde(default)]
    pub tenant_credential_verify_path: Option<String>,
    /// Top-level request-body fields this provider refuses (`deny`) or drops
    /// (`strip`). Enforced per attempt against whichever provider is dialled,
    /// so it holds across fallback.
    #[serde(default)]
    pub request_fields: Option<RequestFields>,
    /// Passive health checking of this provider: after `consecutive_5xx`
    /// consecutive failures the provider is ejected, and aggregates pass it
    /// over until the ejection expires. Lowers to the provider cluster's S6
    /// `outlier_detection`. Absent means no ejection.
    #[serde(default)]
    pub outlier_detection: Option<OutlierDetectionDef>,
    /// Concurrency ceilings of this provider's cluster (S5). Lowers to the
    /// cluster's `DEFAULT`-priority `circuit_breakers` thresholds; a field
    /// left unset keeps the Envoy default of 1024.
    #[serde(default)]
    pub circuit_breakers: Option<CircuitBreakersDef>,
}

/// `providers.<name>.circuit_breakers`: the S5 budgets of one provider
/// cluster. They sit on the provider, never the route (AGENTS.md invariant 6),
/// so each provider of a fallback chain keeps its own ceiling.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitBreakersDef {
    /// Concurrent requests in flight to this provider, streams included.
    #[serde(default)]
    pub max_requests: Option<u32>,
    /// Requests waiting for a connection once `max_connections` is reached.
    #[serde(default)]
    pub max_pending_requests: Option<u32>,
    /// Open upstream connections to this provider.
    #[serde(default)]
    pub max_connections: Option<u32>,
}

/// `providers.<name>.outlier_detection`: the consecutive-failure detector of
/// Envoy's S6 outlier detection, sized for a provider cluster with one
/// upstream host.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutlierDetectionDef {
    /// Consecutive 5xx responses or local failures (connect failure, reset,
    /// timeout) that eject the provider. A 429 does not count. Default 5.
    #[serde(default)]
    pub consecutive_5xx: Option<u32>,
    /// Ejection length for the first ejection; each later ejection of the
    /// same provider lasts this times the ejection count. Default 30s.
    #[serde(default)]
    pub base_ejection_time: Option<SimpleDuration>,
    /// Upper bound on one ejection. Default the larger of 300s and
    /// `base_ejection_time`.
    #[serde(default)]
    pub max_ejection_time: Option<SimpleDuration>,
}

/// `providers.<name>.request_fields`: a generic top-level body-field policy.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestFields {
    /// Requests carrying any of these top-level keys get `400`.
    #[serde(default)]
    pub deny: Vec<String>,
    /// These top-level keys are removed before the request is sent upstream.
    #[serde(default)]
    pub strip: Vec<String>,
}

/// `providers.<name>.protocol`: HTTP version used for this provider's cluster.
/// HTTP/2 multiplexes requests over the per-worker upstream connection cache;
/// some local servers do not support it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamProtocol {
    Http1,
    Http2,
}

/// `auth`: downstream authentication. Mirrors the
/// `api_key`/`api_key_file` shape on [`Provider`] -- exactly one of
/// `hmac_secret`/`hmac_secret_file` -- for the same reason: a secret belongs
/// in the environment or a mounted file, never inlined twice with two
/// conventions for saying so.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Auth {
    #[serde(default)]
    pub hmac_secret: Option<String>,
    #[serde(default)]
    pub hmac_secret_file: Option<String>,
    /// The configured virtual keys. May be empty -- legal (fail closed: an
    /// `auth:` block with no keys authenticates nothing and therefore
    /// refuses every request), but almost certainly a mistake when nothing
    /// else supplies keys, so lowering warns then. A `shared` or
    /// `persistent` store, or an `admin` server, supplies minted keys.
    #[serde(default)]
    pub keys: Vec<AuthKey>,
    /// Where minted keys, revocations, and tenant policy live. Absent means
    /// `in_memory`, the same default Envoy mode uses, so every config written
    /// before this field existed lowers unchanged.
    #[serde(default)]
    pub store: Option<AuthStore>,
    /// The key ring that seals tenant provider credentials at rest
    /// (ADR-0007 decision 2). Absent means the proxy cannot seal or open them.
    #[serde(default)]
    pub tenant_credentials: Option<TenantCredentials>,
    /// Which tenant controls the proxy enforces. Absent means both on.
    #[serde(default)]
    pub enforce: AuthEnforce,
    /// Spend-budget settings. Mirrors the settable fields of
    /// `llmproxy.filters.v0.SpendLimit`. Absent changes nothing.
    #[serde(default)]
    pub spend: Option<AuthSpend>,
    /// How old the policy snapshot may get while the store cannot be read
    /// before virtual-key authentication fails closed (503). Absent means
    /// 4m (5 x the 48 s policy poll). Whole seconds, at least 96s.
    #[serde(default)]
    pub max_policy_staleness: Option<SimpleDuration>,
    /// How long the owner of a stored response or stored chat completion is
    /// kept (ADR-0013 §6). Absent means 720h (30 days). Whole seconds, at
    /// least 1s. Only meaningful with `enforce.object_ownership: true`.
    #[serde(default)]
    pub stored_output_owner_ttl: Option<SimpleDuration>,
    /// JWT/OIDC providers (ADR-0014). Tried in order after virtual keys.
    #[serde(default)]
    pub jwt: Vec<JwtProviderDef>,
    /// Which chargeback tags requests may carry into usage records and
    /// ledger entries. Absent means none: key tags are not copied and the
    /// tag header is never read.
    #[serde(default)]
    pub chargeback_tags: Option<ChargebackTagsDef>,
}

/// `auth.spend`: settings of the `llmproxy.spend_limit` filter that
/// `enforce.spend` adds.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthSpend {
    /// A local file where this replica checkpoints the spend the store has
    /// not yet confirmed, replayed at the next start. Lowers onto
    /// `SpendLimit.recovery_journal_path`. Absent means no journal: spend
    /// accrued while the store cannot be written is lost on a crash.
    #[serde(default)]
    pub recovery_journal_path: Option<String>,
}

/// `auth.chargeback_tags`: the operator's tag allow-list and caps.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChargebackTagsDef {
    /// The tag keys that may be attributed. At least one.
    pub allowed: Vec<AllowedTagDef>,
    /// Read tags from the `x-cost-tags` request header. Absent means false:
    /// the header is never read.
    #[serde(default)]
    pub from_header: bool,
    /// Most tags on one request, 1 to 32. Absent means 8.
    #[serde(default)]
    pub max_tags: Option<u32>,
    /// Longest tag value in bytes, 1 to 256. Absent means 64.
    #[serde(default)]
    pub max_value_bytes: Option<u32>,
}

/// One entry in `auth.chargeback_tags.allowed`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedTagDef {
    pub key: String,
    /// The values the key may take. Absent means any value; an empty list is
    /// an error.
    #[serde(default)]
    pub values: Option<Vec<String>>,
}

/// `auth.enforce`: opt-out switches for the controls that read the admin
/// store. Both default to `true`, so `auth:` alone enforces tenant model
/// allow-lists and spend budgets. Setting one to `false` omits that filter
/// and lowering warns what is left unenforced.
///
/// Rust note: `Default` is written by hand because `#[derive(Default)]` would
/// give `false` for a `bool`, and the safe default here is `true`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthEnforce {
    #[serde(default = "default_true")]
    pub model_policy: bool,
    #[serde(default = "default_true")]
    pub spend: bool,
    /// Enforce tenant and key rate limits set through the admin API
    /// (`PUT /tenants/{id}/limits`, `PUT /keys/{id}/limits`).
    #[serde(default = "default_true")]
    pub limits: bool,
    /// Keep provider objects (files, batches, responses, stored chat
    /// completions, uploads, vector stores, fine-tuning jobs, assistants,
    /// threads, containers, conversations) to the tenant that created them
    /// (`llmproxy.object_ownership`). Every tenant reaches a provider through
    /// one provider account, so the provider cannot tell them apart.
    #[serde(default = "default_true")]
    pub object_ownership: bool,
    /// What a tenant with no stored model policy may use. Absent means
    /// `deny`. Only meaningful with `model_policy: true`; set alongside
    /// `model_policy: false` it is a load error, since nothing would read it.
    #[serde(default)]
    pub tenants_without_policy: Option<TenantsWithoutPolicy>,
}

/// `auth.enforce.tenants_without_policy`. Mirrors
/// `llmproxy.filters.v0.ModelAuthz.TenantsWithoutPolicy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantsWithoutPolicy {
    /// Refuse every model (403) until a policy is stored for the tenant.
    Deny,
    /// Grant every model. Loud at load: every tenant without a policy is
    /// unrestricted.
    Allow,
}

fn default_true() -> bool {
    true
}

impl Default for AuthEnforce {
    fn default() -> Self {
        Self {
            model_policy: true,
            spend: true,
            limits: true,
            object_ownership: true,
            tenants_without_policy: None,
        }
    }
}

/// `auth.tenant_credentials`: the key-encryption keys for tenant provider
/// credentials. Mirrors `llmproxy.filters.v0.TenantCredentials`. Only key
/// file paths appear here; the key bytes are read by the proxy from 0600
/// files, never inlined.
///
/// Rust note: the required fields are `Option`s, not plain `String`s, so a
/// missing one is reported by `lower.rs` at its full dotted path
/// (`auth.tenant_credentials.encryption_key_id`). serde's own missing-field
/// error would name only the enclosing struct.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantCredentials {
    /// Path to the 32-byte key that new tenant credentials are sealed under.
    /// Required and non-empty.
    #[serde(default)]
    pub encryption_key_file: Option<String>,
    /// Names `encryption_key_file`'s key. It is stored in plaintext beside
    /// each sealed credential. Required and non-empty.
    #[serde(default)]
    pub encryption_key_id: Option<String>,
    /// Retired keys, kept decrypt-only so credentials sealed before a
    /// rotation still open. May be empty.
    #[serde(default)]
    pub previous_keys: Vec<PreviousCredentialKey>,
}

/// One entry in `auth.tenant_credentials.previous_keys`. Both fields are
/// required and non-empty; see [`TenantCredentials`] for why they are
/// `Option`s.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviousCredentialKey {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub file: Option<String>,
}

/// `auth.store`: exactly one of three members, mirroring the `store` oneof on
/// `llmproxy.filters.v0.Authentication`. Only these three are accepted --
/// Envoy mode's `store` has no other members, so the dialect exposes no more.
/// Exactly-one is checked in `lower.rs`, the same way `hmac_secret` /
/// `hmac_secret_file` is, so a doubled or empty `store` is reported at
/// `auth.store` by name.
///
/// Rust note: this is a struct of `Option`s rather than a serde enum. An
/// externally tagged enum would read as `store: !persistent {...}` in YAML
/// (serde_yaml's tag syntax), not the `store: { persistent: {...} }` every
/// other dialect block uses.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthStore {
    /// Keys and policy live only for the life of the process. Written as
    /// `in_memory: {}`; the empty map exists so the shape stays a map.
    #[serde(default)]
    pub in_memory: Option<InMemoryStore>,
    #[serde(default)]
    pub persistent: Option<PersistentStore>,
    #[serde(default)]
    pub shared: Option<SharedStore>,
}

/// `auth.store.in_memory`. Takes no fields.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InMemoryStore {}

/// `auth.store.persistent`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentStore {
    /// Path to the redb database file. Created if it does not exist. Required
    /// and non-empty: an empty path is an error, never a silent fall back to
    /// `in_memory`, which would lose every key minted at runtime.
    pub path: String,
}

/// `auth.store.shared`. Mirrors `hmac_secret`/`hmac_secret_file`: exactly one
/// of `url`/`url_file`, because a Redis URL may embed a password and so
/// belongs in the environment or a mounted file.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedStore {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub url_file: Option<String>,
    /// Prefixes every Redis key this store touches. Unset or empty means the
    /// built-in default, same as Envoy mode.
    #[serde(default)]
    pub namespace: Option<String>,
}

// Rust note: hand-written rather than derived, for the same reason
// `proxy-filters`' `StoreSpec` has a hand-written `Debug`: a derived impl would
// print `url`, and a Redis URL may carry a password. `Auth` derives `Debug`
// and holds this struct, so the redaction has to live here.
impl std::fmt::Debug for SharedStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedStore")
            .field("url", &self.url.as_ref().map(|_| "<redacted>"))
            .field("url_file", &self.url_file)
            .field("namespace", &self.namespace)
            .finish()
    }
}

/// One entry in `auth.keys`. The plaintext key never appears in
/// configuration -- only a keyed digest of it (`digest`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthKey {
    /// Names this credential in audit logs. Must be unique within `auth.keys`.
    pub id: String,
    /// The tenant (account/team) this key authenticates as. Several keys may
    /// share a tenant; that's the normal case.
    pub tenant: String,
    /// Lowercase hex of `HMAC-SHA256(hmac_secret, <plaintext key>)`, exactly
    /// 64 characters.
    pub digest: String,
    #[serde(default)]
    pub revoked: bool,
    /// Chargeback tags for requests this key authenticates (key metadata).
    /// `auth.chargeback_tags` decides which are attributed.
    #[serde(default)]
    pub tags: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderType {
    Openai,
    Anthropic,
    OpenaiCompatible,
    /// OpenRouter serves OpenAI-shaped requests under `/api/v1`.
    Openrouter,
    /// OpenAI-shaped API hosted on Azure. The provider requires deployment
    /// and api-version fields to build its provider-owned URL template.
    AzureOpenai,
    /// Serves Anthropic-shaped Claude, Google-shaped Gemini, and
    /// OpenAI-shaped Kimi under one provider type. Its dialect cannot be
    /// derived from the type alone -- see [`Self::dialect_is_ambiguous`].
    Vertex,
    /// Serves multiple wire formats like Vertex. Per-request authentication
    /// uses AWS SigV4. Also dialect-ambiguous -- see
    /// [`Self::dialect_is_ambiguous`].
    Bedrock,
}

impl ProviderType {
    pub fn as_str(self) -> &'static str {
        match self {
            ProviderType::Openai => "openai",
            ProviderType::Anthropic => "anthropic",
            ProviderType::OpenaiCompatible => "openai-compatible",
            ProviderType::Openrouter => "openrouter",
            ProviderType::AzureOpenai => "azure-openai",
            ProviderType::Vertex => "vertex",
            ProviderType::Bedrock => "bedrock",
        }
    }

    /// Whether this type serves more than one wire format, so a `models:`
    /// backend of this type must set `dialect` explicitly instead of
    /// deriving it. Only `vertex` and `bedrock` today.
    pub fn dialect_is_ambiguous(self) -> bool {
        matches!(self, ProviderType::Vertex | ProviderType::Bedrock)
    }
}

/// `models.<name>`: one logical model and the providers able to serve it.
/// There is deliberately no separate noun for an entry here: the config
/// surface has exactly two -- `providers` (the top-level map) and `models`
/// -- so an entry in this list is just a provider reference, the same
/// `ProviderModelRef` `routes` already uses, with an object form alongside
/// it for when `dialect` must be explicit.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelDef {
    /// Tried in priority order, or, with `weight` on every entry, starting
    /// at a provider picked in proportion to weight. A multi-provider model
    /// lowers to aggregate clusters, and each retry advances to the next
    /// provider (see `lower_model`). Every entry is validated; a bad one
    /// fails the load (AGENTS.md invariant 1).
    pub providers: Vec<ModelProviderRef>,
    /// Upper bound on the output tokens a request for this model may ask for.
    /// A request asking for more is refused with 400; the body is never
    /// rewritten. Positive. Unset means no cap. Lowers to the `llmproxy.body_rewrite`
    /// per-route override on this model's route.
    #[serde(default)]
    pub max_output_tokens: Option<u32>,
    /// Pins a session to one weighted provider (ADR-0016). Lowers to Envoy
    /// `weighted_clusters.use_hash_policy` plus a route `hash_policy`; needs
    /// weights on `providers`.
    #[serde(default)]
    pub session_affinity: Option<SessionAffinity>,
    /// How a weighted alias picks its first provider for a request with no
    /// session: by weight alone (the default) or by weight scaled by
    /// measured latency. Lowers to route metadata `io.llmproxy.selection`
    /// (`envoy-divergences.md` row 48); needs weights on `providers`.
    #[serde(default)]
    pub selection: ModelSelection,
}

/// `models.<name>.selection`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelSelection {
    #[default]
    Weighted,
    Latency,
}

/// `models.<name>.session_affinity`: where a request's session key comes
/// from. At least one of the two is set.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionAffinity {
    /// Request header carrying the session key; checked first.
    #[serde(default)]
    pub header: Option<String>,
    /// Authenticated identity used when the header is absent.
    #[serde(default)]
    pub identity: Option<AffinityIdentity>,
}

/// `models.<name>.session_affinity.identity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AffinityIdentity {
    Key,
    User,
    Tenant,
}

/// One entry in a [`ModelDef`]'s `providers` list: either the shorthand
/// string form (`provider` or `provider/model`, reusing [`ProviderModelRef`]
/// exactly as `routes` does), or the object form needed whenever `dialect`
/// must be set explicitly. Rust note: `#[serde(untagged)]` tries each
/// variant's `Deserialize` in order and keeps the first that succeeds --
/// same shape as [`Listen`]'s `Address(String) | Full(ListenerSpec)`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ModelProviderRef {
    Shorthand(ProviderModelRef),
    Full(ModelProvider),
}

impl ModelProviderRef {
    pub fn provider(&self) -> &str {
        match self {
            ModelProviderRef::Shorthand(r) => &r.provider,
            ModelProviderRef::Full(p) => &p.provider,
        }
    }

    pub fn model(&self) -> Option<&str> {
        match self {
            ModelProviderRef::Shorthand(r) => r.model.as_deref(),
            ModelProviderRef::Full(p) => p.model.as_deref(),
        }
    }

    /// The shorthand string form has nowhere to put a `dialect` -- it is
    /// always `None` there, never inferred from anything about the string.
    pub fn dialect(&self) -> Option<Dialect> {
        match self {
            ModelProviderRef::Shorthand(_) => None,
            ModelProviderRef::Full(p) => p.dialect,
        }
    }

    /// The shorthand string form cannot carry a `weight` either.
    pub fn weight(&self) -> Option<u32> {
        match self {
            ModelProviderRef::Shorthand(_) => None,
            ModelProviderRef::Full(p) => p.weight,
        }
    }
}

/// The object form of a [`ModelProviderRef`]: needed whenever `dialect` must
/// be explicit, since the shorthand string form cannot carry it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelProvider {
    /// Key into `providers`.
    pub provider: String,
    /// Upstream model ID at this provider, if different from the model's
    /// own catalogue name (e.g. Anthropic's dated model IDs). Recorded;
    /// substituting it into the request body needs the request-body
    /// rewriter, so this produces a translate-time warning until
    /// then and the client's original model name is forwarded as-is.
    #[serde(default)]
    pub model: Option<String>,
    /// Wire dialect this provider entry speaks. Optional (and derived from
    /// the provider's `type`) for `openai`/`anthropic`/`openai-compatible`/
    /// `azure-openai`, whose wire format the type alone determines.
    /// REQUIRED for `vertex`/`bedrock` (see
    /// [`ProviderType::dialect_is_ambiguous`]) -- omitting it there is a
    /// load error, never a guess. The shorthand string form of
    /// [`ModelProviderRef`] cannot express this field at all, so an
    /// ambiguous-type provider used in `models:` must use this object form.
    #[serde(default)]
    pub dialect: Option<Dialect>,
    /// Share of this alias's requests that start at this provider. Set on
    /// every entry or on none. With weights, each request picks its first
    /// provider in proportion to weight, once, and the other entries stay its
    /// fallback chain in list order. `0` makes an entry fallback-only. Lowers
    /// to Envoy `weighted_clusters` (S1.5); see `lower_model`.
    #[serde(default)]
    pub weight: Option<u32>,
}

/// A provider entry's wire format, for provider types whose dialect the type
/// alone doesn't determine. Matches the strings `lower::usage_dialect`
/// derives for the unambiguous provider types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Dialect {
    Openai,
    Anthropic,
}

impl Dialect {
    pub fn as_str(self) -> &'static str {
        match self {
            Dialect::Openai => "openai",
            Dialect::Anthropic => "anthropic",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRule {
    /// Model glob: `*` matches any run of characters; case-sensitive.
    pub model: String,
    pub provider: ProviderModelRef,
    #[serde(default)]
    pub fallbacks: Vec<ProviderModelRef>,
    #[serde(default)]
    pub retries: Option<Retries>,
    #[serde(default)]
    pub idle_timeout: Option<SimpleDuration>,
    /// Require every filter serving this route to flush response bytes through.
    #[serde(default)]
    pub streaming: Option<StreamingMode>,
}

/// The v0 dialect's route-level streaming assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StreamingMode {
    Strict,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Retries {
    /// Extra attempts against the primary provider; 0 disables. Max 5.
    pub attempts: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limit {
    pub key: LimitKey,
    #[serde(default)]
    pub tokens_per_minute: Option<TokenAmount>,
    #[serde(default)]
    pub requests_per_minute: Option<TokenAmount>,
    #[serde(default)]
    pub concurrent_sessions: Option<u64>,
    #[serde(default)]
    pub models: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observability {
    #[serde(default)]
    pub access_logs: Option<AccessLogs>,
    /// Forces `stream_options.include_usage = true` onto streaming OpenAI-
    /// dialect requests, including ones where the client asked for no usage
    /// (`include_usage: false`), so the usage filter always has a final SSE
    /// frame to read tokens off of. Defaults to `true`, both when
    /// this key is absent AND when the whole `observability` block is absent
    /// -- see `default_force_usage_reporting`.
    #[serde(default = "default_force_usage_reporting")]
    pub force_usage_reporting: bool,
    /// OTLP trace export: config surface only, see
    /// `proxy_config::ir::TracingConfig`'s doc for what does (and does not)
    /// consume this yet. `None` -- both when this key is absent and when the
    /// whole `observability` block is absent -- means tracing is off.
    #[serde(default)]
    pub tracing: Option<Tracing>,
    /// OTLP metric export. **Independent of [`Self::tracing`]**, and that
    /// independence is the point: an operator can export metrics with tracing
    /// entirely off, and turning tracing off does not stop metrics. Before
    /// this field existed the only OTLP configuration in the proxy was
    /// `observability.tracing`, and the metric exporter was constructed inside
    /// the task spawned for it -- so a config with no `tracing` block exported
    /// no metrics over OTLP at all, even though the registry those metrics are
    /// read from is always populated and `/stats/prometheus` works with no
    /// OTLP configuration of any kind. `None` -- when this key is absent, or
    /// when the whole `observability` block is absent -- means no OTLP metric
    /// export, which says nothing about whether metrics are being collected.
    #[serde(default)]
    pub metrics: Option<Metrics>,
    /// Trace export (ADR-0008): one captured record per request for tenants
    /// that opt in through tenant policy. Requires the top-level `auth` block.
    /// Absent means no trace export.
    #[serde(default)]
    pub traces: Option<Traces>,
    /// Name the serving provider, the attempt count and the providers tried
    /// on every response. Lowers to the virtual host's
    /// `include_attempt_count_in_response` plus metadata
    /// `io.llmproxy.routing_headers` (`envoy-divergences.md` row 49). Off by
    /// default: it discloses the operator's routing to callers.
    #[serde(default)]
    pub routing_headers: bool,
}

/// `observability.traces`: lowers to `node.metadata["io.llmproxy.traces"]`,
/// which owns the defaults and range checks. Required fields are `Option`s so
/// a missing one is reported at `observability.traces.<field>` rather than as
/// serde's missing field on the enclosing block.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Traces {
    #[serde(default)]
    pub directory: Option<String>,
    #[serde(default)]
    pub max_disk_bytes: Option<u64>,
    /// Directory destination only; rejected together with `s3`.
    #[serde(default)]
    pub max_age: Option<SimpleDuration>,
    /// Unset means `gzip`.
    #[serde(default)]
    pub codec: Option<TraceCodec>,
    #[serde(default)]
    pub zstd_window_log: Option<u64>,
    #[serde(default)]
    pub max_request_body_bytes: Option<u64>,
    #[serde(default)]
    pub max_response_body_bytes: Option<u64>,
    #[serde(default)]
    pub max_memory_bytes: Option<u64>,
    #[serde(default)]
    pub max_queued_traces: Option<u64>,
    #[serde(default)]
    pub segment_max_bytes: Option<u64>,
    #[serde(default)]
    pub segment_max_age: Option<SimpleDuration>,
    #[serde(default)]
    pub max_open_segments: Option<u64>,
    #[serde(default)]
    pub s3: Option<TracesS3>,
}

/// `observability.traces.codec`: how sealed segments are compressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceCodec {
    Gzip,
    Zstd,
}

/// `observability.traces.s3`: an S3-compatible upload destination.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TracesS3 {
    #[serde(default)]
    pub bucket: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub path_style: Option<bool>,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub access_key_id: Option<String>,
    #[serde(default)]
    pub secret_access_key: Option<String>,
    #[serde(default)]
    pub session_token: Option<String>,
    #[serde(default)]
    pub upload_timeout: Option<SimpleDuration>,
}

/// `observability.tracing`. The top-level `tracing` key is RESERVED and
/// rejected in v0 (see [`RESERVED_KEYS`]) precisely so this nested block can
/// exist without a collision once tracing has more than config-surface
/// behavior.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tracing {
    /// Required (and must be non-empty) when this block is present -- there
    /// is no sensible destination to guess. `Option` rather than a plain
    /// (serde-required) `String` so `crate::lower` can report a full
    /// `observability.tracing.otlp_endpoint` path on both "missing" and
    /// "empty", instead of serde's coarser "missing field" error scoped only
    /// to the enclosing `tracing` block -- same reasoning as `Auth`'s
    /// `hmac_secret`/`hmac_secret_file` choice.
    #[serde(default)]
    pub otlp_endpoint: Option<String>,
    /// OTLP resource attribute `service.name`. Default: `"llm-proxy"`.
    #[serde(default = "default_tracing_service_name")]
    pub service_name: String,
    /// Head-sampling ratio for a newly minted root span, checked against
    /// `0.0..=1.0` at lowering (this type only parses a plain `f64`).
    /// Default: `1.0`.
    #[serde(default = "default_tracing_sample_ratio")]
    pub sample_ratio: f64,
    /// Per-export deadline for trace-batch RPCs. Default: `"5s"`. Bounds a
    /// collector that accepts the connection and then stops responding; the
    /// Envoy-mode reader also enforces `100ms..=60s`, and rejects the field at
    /// load with a full dotted path if it is outside that band. Optional --
    /// the deadline is a tuning knob, not a required decision.
    #[serde(default = "default_tracing_export_deadline")]
    pub export_deadline: SimpleDuration,
}

fn default_tracing_export_deadline() -> SimpleDuration {
    SimpleDuration(Duration::from_secs(5))
}

/// `observability.metrics`. Deliberately a sibling of [`Tracing`] rather than
/// extra keys on it: see [`Observability::metrics`]'s doc for why metric export
/// has to be expressible with tracing off.
///
/// `export_interval`/`export_deadline` reuse the same [`SimpleDuration`] string
/// syntax as the rest of this dialect (`"30s"`, `"5m"`, ...) rather than raw
/// seconds numbers, for the same reason every other timeout here does: a bare
/// number next to a field named `export_interval` is a unit guessing game, and
/// this dialect already made that choice once.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metrics {
    /// Required (and must be non-empty) when this block is present -- there is
    /// no sensible destination to guess. `Option` for the same
    /// full-dotted-path-on-both-missing-and-empty reason as
    /// [`Tracing::otlp_endpoint`].
    #[serde(default)]
    pub otlp_endpoint: Option<String>,
    /// OTLP resource attribute `service.name`. Default: `"llm-proxy"`.
    #[serde(default = "default_tracing_service_name")]
    pub service_name: String,
    /// How often to snapshot and export the registry. Default: `"15s"`.
    #[serde(default = "default_metrics_export_interval")]
    pub export_interval: SimpleDuration,
    /// Per-export deadline. Default: `"10s"`. Validated at lowering to be
    /// shorter than `export_interval` -- see
    /// `proxy_config::ir::MetricsExportConfig::export_deadline` for why a
    /// deadline at or above the interval is a configuration that cannot do
    /// what it looks like it does.
    #[serde(default = "default_metrics_export_deadline")]
    pub export_deadline: SimpleDuration,
}

fn default_metrics_export_interval() -> SimpleDuration {
    SimpleDuration(Duration::from_secs(15))
}

fn default_metrics_export_deadline() -> SimpleDuration {
    SimpleDuration(Duration::from_secs(10))
}

fn default_tracing_service_name() -> String {
    "llm-proxy".to_string()
}

fn default_tracing_sample_ratio() -> f64 {
    1.0
}

/// `pub(crate)`, not private: `lower.rs`'s `force_usage_reporting` needs the
/// exact same default for the "whole `observability` block is absent" case
/// -- serde's `#[serde(default = ...)]` only ever fires when the struct
/// itself is present, so that case has to reuse this function rather than
/// hardcode `true` a second time (two copies of the same default is exactly
/// the kind of thing that drifts silently).
pub(crate) fn default_force_usage_reporting() -> bool {
    true
}

/// Strict rate-card configuration. Exactly one source is required so a
/// file can never silently override an inline list (or vice versa).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pricing {
    /// Public source metadata, carried to the admin pricing inventory.
    #[serde(default)]
    pub catalog: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default)]
    pub price_list_file: Option<String>,
    #[serde(default)]
    pub price_list: Option<PriceListDef>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriceListDef {
    #[serde(default)]
    pub version: Option<String>,
    pub effective_from: String,
    pub entries: Vec<PriceEntryDef>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriceEntryDef {
    #[serde(default)]
    pub cached_input_unpriced: bool,
    #[serde(default)]
    pub cache_write_unpriced: bool,
    pub provider_type: String,
    pub model: String,
    /// Required even for a one-tier entry: a later edit adding tiers must not
    /// change money semantics by guessing a default.
    #[serde(default)]
    pub tier_mode: Option<TierModeDef>,
    #[serde(default)]
    pub tiers: Vec<TierDef>,
    /// What the entry meters. Absent means `tokens`, today's behaviour.
    #[serde(default)]
    pub basis: Option<PriceBasisDef>,
    /// Per-image rows; present only for a `basis: images` entry.
    #[serde(default)]
    pub image_prices: Option<Vec<ImagePriceDef>>,
    /// The price of one input character; present only for a
    /// `basis: characters` entry.
    #[serde(default)]
    pub nanodollars_per_character: Option<u64>,
    /// The price of one second of audio; present only for a
    /// `basis: audio_seconds` entry.
    #[serde(default)]
    pub nanodollars_per_second: Option<u64>,
}

/// What a rate-card entry prices (ADR-0010 decision 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriceBasisDef {
    Tokens,
    Images,
    Characters,
    AudioSeconds,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImagePriceDef {
    #[serde(default)]
    pub size: Option<String>,
    #[serde(default)]
    pub quality: Option<String>,
    pub nanodollars_per_image: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TierDef {
    #[serde(default)]
    pub up_to: Option<u64>,
    pub input_nanodollars_per_token: u64,
    pub cached_input_nanodollars_per_token: u64,
    pub cache_write_nanodollars_per_token: u64,
    pub output_nanodollars_per_token: u64,
    #[serde(default)]
    pub image_input_nanodollars_per_token: Option<u64>,
    #[serde(default)]
    pub image_output_nanodollars_per_token: Option<u64>,
    #[serde(default)]
    pub audio_input_nanodollars_per_token: Option<u64>,
    #[serde(default)]
    pub audio_output_nanodollars_per_token: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TierModeDef {
    WholeRequest,
    Graduated,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessLogs {
    #[serde(default = "default_log_output")]
    pub output: String,
    #[serde(default)]
    pub format: LogFormat,
}

fn default_log_output() -> String {
    "stdout".to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

// ------------------------------------------------------- constrained scalars --

/// A duration like `500ms`, `30s`, `5m`, `1h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct SimpleDuration(pub Duration);

impl TryFrom<String> for SimpleDuration {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        let (digits, unit): (String, String) = {
            let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
            (s[..split].to_string(), s[split..].to_string())
        };
        let n: u64 = digits
            .parse()
            .map_err(|_| format!("`{s}` is not a duration (expected e.g. 500ms, 30s, 5m, 1h)"))?;
        let dur = match unit.as_str() {
            "ms" => Duration::from_millis(n),
            "s" => Duration::from_secs(n),
            "m" => Duration::from_secs(n * 60),
            "h" => Duration::from_secs(n * 3600),
            _ => {
                return Err(format!(
                    "`{s}` has an unknown unit (expected ms, s, m, or h)"
                ))
            }
        };
        Ok(Self(dur))
    }
}

impl fmt::Display for SimpleDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // proto3-JSON duration form, e.g. "5s" / "0.25s".
        write!(f, "{}s", self.0.as_secs_f64())
    }
}

/// A token count: a plain integer, or `100k` / `2m`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "TokenAmountRepr")]
pub struct TokenAmount(pub u64);

#[derive(Deserialize)]
#[serde(untagged)]
pub enum TokenAmountRepr {
    Int(u64),
    Str(String),
}

impl TryFrom<TokenAmountRepr> for TokenAmount {
    type Error = String;
    fn try_from(repr: TokenAmountRepr) -> Result<Self, Self::Error> {
        match repr {
            TokenAmountRepr::Int(0) => Err("token amount must be at least 1".to_string()),
            TokenAmountRepr::Int(n) => Ok(Self(n)),
            TokenAmountRepr::Str(s) => {
                let (mult, digits) = match s.strip_suffix(['k', 'm']) {
                    Some(d) if s.ends_with('k') => (1_000, d),
                    Some(d) => (1_000_000, d),
                    None => {
                        return Err(format!(
                            "`{s}` is not a token amount (expected an integer or e.g. 100k, 2m)"
                        ))
                    }
                };
                let n: u64 = digits
                    .parse()
                    .map_err(|_| format!("`{s}` is not a token amount"))?;
                Ok(Self(n * mult))
            }
        }
    }
}

/// `provider-name` or `provider-name/model-name` (model rewrite).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct ProviderModelRef {
    pub provider: String,
    pub model: Option<String>,
}

impl TryFrom<String> for ProviderModelRef {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        let (provider, model) = match s.split_once('/') {
            Some((p, m)) => (p.to_string(), Some(m.to_string())),
            None => (s.clone(), None),
        };
        if !is_valid_provider_name(&provider) {
            return Err(format!(
                "`{s}` is not a provider reference (expected `provider` or `provider/model`, \
                 lowercase letters/digits/hyphens)"
            ));
        }
        if model.as_deref() == Some("") {
            return Err(format!("`{s}` has an empty model name after `/`"));
        }
        Ok(Self { provider, model })
    }
}

pub fn is_valid_provider_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    match bytes.next() {
        Some(b) if b.is_ascii_lowercase() || b.is_ascii_digit() => {}
        _ => return false,
    }
    bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `global`, `client-ip`, `tenant`, or `header:<name>`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum LimitKey {
    Global,
    ClientIp,
    Header(String),
    /// One bucket per authenticated tenant.
    /// Requires an `auth:` block -- without one, nothing would authenticate
    /// a tenant, so configuring this key is a load error rather than a
    /// silent fallback to bucketing on a client-supplied header.
    Tenant,
}

impl TryFrom<String> for LimitKey {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.as_str() {
            "global" => Ok(Self::Global),
            "client-ip" => Ok(Self::ClientIp),
            "tenant" => Ok(Self::Tenant),
            _ => match s.strip_prefix("header:") {
                Some(name)
                    if !name.is_empty()
                        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') =>
                {
                    Ok(Self::Header(name.to_string()))
                }
                _ => Err(format!(
                    "`{s}` is not a limit key (expected `global`, `client-ip`, `tenant`, or \
                     `header:<name>`)"
                )),
            },
        }
    }
}

impl Provider {
    /// Effective provider type: explicit `type`, else inferred from the name
    /// (`openai`/`anthropic`/`openrouter`), else openai-compatible.
    pub fn effective_type(&self, name: &str) -> ProviderType {
        self.provider_type.unwrap_or(match name {
            "openai" => ProviderType::Openai,
            "anthropic" => ProviderType::Anthropic,
            "openrouter" => ProviderType::Openrouter,
            _ => ProviderType::OpenaiCompatible,
        })
    }

    /// Effective base URL: explicit, else implied by the effective type.
    pub fn effective_base_url(&self, name: &str) -> Option<String> {
        self.base_url.clone().or(match self.effective_type(name) {
            ProviderType::Openai => Some("https://api.openai.com".to_string()),
            ProviderType::Anthropic => Some("https://api.anthropic.com".to_string()),
            ProviderType::Openrouter => Some("https://openrouter.ai".to_string()),
            // These provider types require an explicit base URL. Azure,
            // Vertex, and Bedrock use provider-specific request handling.
            ProviderType::OpenaiCompatible
            | ProviderType::AzureOpenai
            | ProviderType::Vertex
            | ProviderType::Bedrock => None,
        })
    }
}
