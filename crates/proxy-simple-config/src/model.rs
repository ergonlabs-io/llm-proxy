//! The v0 dialect data model — a 1:1 mirror of `schema/llmproxy-v0.schema.json`.
//!
//! The schema file is normative; this module implements it and must never
//! accept anything the schema does not define (`deny_unknown_fields`
//! everywhere) nor extend it. Scalar types with constrained shapes (durations,
//! token amounts, provider refs, limit keys) parse eagerly via
//! `#[serde(try_from = "String")]`, so shape errors surface at load with the
//! offending field's path.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

/// Top-level keys reserved for future schema versions; rejected in v0 so they
/// can be added compatibly later.
pub const RESERVED_KEYS: &[&str] = &["envoy", "tracing", "clusters"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimpleConfig {
    /// Must be 0 (checked in semantic validation for a friendlier error).
    pub version: u64,
    #[serde(default)]
    pub listen: Option<Listen>,
    #[serde(default)]
    pub admin: Option<String>,
    /// Downstream authentication (WP-50 increment 2a-iii). Absent means the
    /// proxy admits every request unauthenticated, same as today. Present,
    /// even with `keys: []`, switches the listener to fail-closed.
    #[serde(default)]
    pub auth: Option<Auth>,
    /// Rust note: `BTreeMap` (not `HashMap`) keeps providers sorted by name,
    /// making the lowered Envoy config deterministic — same input, same output.
    pub providers: BTreeMap<String, Provider>,
    /// Logical models (WP-49): a client-facing name mapped to an ordered
    /// list of backends able to serve it. Each entry gets an implicit route
    /// matching its name (exactly, or by wildcard precedence -- WP-49
    /// increment 2, see `lower::model_catalog_order`), in addition to
    /// whatever `routes` express. `BTreeMap` for the same determinism reason
    /// as `providers`; `deserialize_with` on top of that catches a literal
    /// duplicate key, which a plain `BTreeMap` deserialize would otherwise
    /// silently collapse to "last one wins" (see `deserialize_model_catalog`).
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
}

/// Deserializes `models:` into a `BTreeMap`, erroring on a literal duplicate
/// key instead of silently keeping only the last one (WP-49 increment 2:
/// "a genuine tie ... is a config-load error naming both offenders, never a
/// silent pick" -- ground rule #1 applies to ambiguity, not just unknown
/// fields). `serde`'s own blanket `BTreeMap` deserialize can't tell us this:
/// it inserts key by key, so a repeated key just overwrites the earlier
/// entry before we ever see it. Rust note: this is a hand-written
/// `Deserialize`-shaped visitor (via `deserialize_with`, so it plugs into
/// `#[derive(Deserialize)]` for the one field that needs different behavior)
/// -- `visit_map` gets one `(key, value)` pair at a time off the underlying
/// YAML mapping, same protocol serde's own container `Deserialize` impls use.
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
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenTls {
    pub cert_file: String,
    pub key_file: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    #[serde(default, rename = "type")]
    pub provider_type: Option<ProviderType>,
    #[serde(default)]
    pub base_url: Option<String>,
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
}

/// `providers.<name>.protocol`: which HTTP version the proxy dials this
/// provider's cluster with. `http1` connects once per request; `http2`
/// reaches the per-worker upstream connection cache
/// (`proxy_http::upstream_pool`, WP-15 slice A), multiplexing every
/// concurrent request over one connection per (cluster, address). Most
/// hosted providers support it; many local/self-hosted plaintext servers do
/// not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamProtocol {
    Http1,
    Http2,
}

/// `auth`: downstream authentication (WP-50 increment 2a-iii). Mirrors the
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
    /// refuses every request), but almost certainly a mistake, so lowering
    /// warns rather than silently accepting it.
    #[serde(default)]
    pub keys: Vec<AuthKey>,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderType {
    Openai,
    Anthropic,
    OpenaiCompatible,
    /// OpenAI-shaped API hosted on Azure -- an unambiguous dialect (always
    /// OpenAI's), but the endpoint needs a deployment-name + `api-version`
    /// URL template that isn't built yet. Loading one is a hard error; see
    /// `lower::lower_provider`.
    AzureOpenai,
    /// Serves Anthropic-shaped Claude, Google-shaped Gemini, and
    /// OpenAI-shaped Kimi under one provider type, and needs minted OAuth2
    /// with a refresh loop -- not built yet. Loading one is a hard error;
    /// see `lower::lower_provider`. Its dialect cannot be derived from the
    /// type alone -- see [`Self::dialect_is_ambiguous`].
    Vertex,
    /// Serves multiple wire formats like Vertex, and needs per-request
    /// SigV4 signing over the canonical request (which must run after body
    /// rewriting, so it cannot be header injection) -- not built yet.
    /// Loading one is a hard error; see `lower::lower_provider`. Also
    /// dialect-ambiguous -- see [`Self::dialect_is_ambiguous`].
    Bedrock,
}

impl ProviderType {
    pub fn as_str(self) -> &'static str {
        match self {
            ProviderType::Openai => "openai",
            ProviderType::Anthropic => "anthropic",
            ProviderType::OpenaiCompatible => "openai-compatible",
            ProviderType::AzureOpenai => "azure-openai",
            ProviderType::Vertex => "vertex",
            ProviderType::Bedrock => "bedrock",
        }
    }

    /// Whether this type serves more than one wire format, so a `models:`
    /// backend of this type must set `dialect` explicitly instead of
    /// deriving it (WP-49). Only `vertex` and `bedrock` today.
    pub fn dialect_is_ambiguous(self) -> bool {
        matches!(self, ProviderType::Vertex | ProviderType::Bedrock)
    }
}

/// `models.<name>`: one logical model and the providers able to serve it
/// (WP-49). Naming and data model only in this increment -- which entry
/// actually gets picked (fallback / weighted split / cost-aware) is WP-35.
/// There is deliberately no separate noun for an entry here: the config
/// surface has exactly two -- `providers` (the top-level map) and `models`
/// -- so an entry in this list is just a provider reference, the same
/// `ProviderModelRef` `routes` already uses, with an object form alongside
/// it for when `dialect` must be explicit.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelDef {
    /// Tried in priority order. WP-49 increment 1: only `providers[0]` is
    /// ever selected to serve traffic -- every later entry is still
    /// validated (a bad one still fails to load, ground rule #1) but gets a
    /// translate-time warning instead of being used.
    pub providers: Vec<ModelProviderRef>,
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
    /// rewriter (WP-35), so this produces a translate-time warning until
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
    /// dialect requests that didn't already opt in, so the usage filter has
    /// a final SSE frame to read tokens off of. Defaults to `true`, both when
    /// this key is absent AND when the whole `observability` block is absent
    /// -- see `default_force_usage_reporting`.
    #[serde(default = "default_force_usage_reporting")]
    pub force_usage_reporting: bool,
    /// OTLP trace export (WP-51 increment 3): config surface only, see
    /// `proxy_config::ir::TracingConfig`'s doc for what does (and does not)
    /// consume this yet. `None` -- both when this key is absent and when the
    /// whole `observability` block is absent -- means tracing is off.
    #[serde(default)]
    pub tracing: Option<Tracing>,
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

/// Strict WP-53 rate-card configuration. Exactly one source is required so a
/// file can never silently override an inline list (or vice versa).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pricing {
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
    pub provider_type: String,
    pub model: String,
    /// Required even for a one-tier entry: a later edit adding tiers must not
    /// change money semantics by guessing a default.
    #[serde(default)]
    pub tier_mode: Option<TierModeDef>,
    pub tiers: Vec<TierDef>,
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
    /// One bucket per authenticated tenant (WP-50 increment 2a-iii).
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
    /// (`openai`/`anthropic`), else openai-compatible.
    pub fn effective_type(&self, name: &str) -> ProviderType {
        self.provider_type.unwrap_or(match name {
            "openai" => ProviderType::Openai,
            "anthropic" => ProviderType::Anthropic,
            _ => ProviderType::OpenaiCompatible,
        })
    }

    /// Effective base URL: explicit, else implied by the effective type.
    pub fn effective_base_url(&self, name: &str) -> Option<String> {
        self.base_url.clone().or(match self.effective_type(name) {
            ProviderType::Openai => Some("https://api.openai.com".to_string()),
            ProviderType::Anthropic => Some("https://api.anthropic.com".to_string()),
            // No implied URL built yet for these three -- their credential
            // scheme isn't implemented either (see
            // `lower::lower_provider`), so an explicit `base_url` here
            // wouldn't get a config past lowering anyway.
            ProviderType::OpenaiCompatible
            | ProviderType::AzureOpenai
            | ProviderType::Vertex
            | ProviderType::Bedrock => None,
        })
    }
}
