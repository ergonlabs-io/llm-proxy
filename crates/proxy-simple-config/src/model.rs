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

use serde::Deserialize;

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
    /// Rust note: `BTreeMap` (not `HashMap`) keeps providers sorted by name,
    /// making the lowered Envoy config deterministic — same input, same output.
    pub providers: BTreeMap<String, Provider>,
    pub routes: Vec<RouteRule>,
    #[serde(default)]
    pub limits: Vec<Limit>,
    #[serde(default)]
    pub observability: Option<Observability>,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderType {
    Openai,
    Anthropic,
    OpenaiCompatible,
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

/// `global`, `client-ip`, or `header:<name>`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum LimitKey {
    Global,
    ClientIp,
    Header(String),
}

impl TryFrom<String> for LimitKey {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.as_str() {
            "global" => Ok(Self::Global),
            "client-ip" => Ok(Self::ClientIp),
            _ => match s.strip_prefix("header:") {
                Some(name)
                    if !name.is_empty()
                        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') =>
                {
                    Ok(Self::Header(name.to_string()))
                }
                _ => Err(format!(
                    "`{s}` is not a limit key (expected `global`, `client-ip`, or `header:<name>`)"
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
            ProviderType::OpenaiCompatible => None,
        })
    }
}
