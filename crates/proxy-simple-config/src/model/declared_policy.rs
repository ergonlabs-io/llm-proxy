//! `auth.declared_policy`: tenants, model policies, budgets, scoped budgets
//! and limits declared in the config file. Lowers onto
//! `llmproxy.filters.v0.Authentication.declared_policy`.
//!
//! Rust note: required fields are `Option`s, as on [`super::TenantCredentials`],
//! so a missing one is reported by the lowering at its full dotted path
//! (`auth.declared_policy.revision`) rather than by serde naming only the
//! struct.

use std::fmt;

use serde::de::value::MapAccessDeserializer;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

/// `auth.declared_policy`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredPolicyDef {
    /// Required, at least 1. Orders this file against others that share a
    /// store.
    #[serde(default)]
    pub revision: Option<u64>,
    /// The declared tenants. May be empty.
    #[serde(default)]
    pub tenants: Vec<DeclaredTenantDef>,
}

/// One entry in `auth.declared_policy.tenants`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredTenantDef {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub policy: Option<DeclaredModelPolicyDef>,
    #[serde(default)]
    pub budget: Option<DeclaredBudgetDef>,
    #[serde(default)]
    pub scoped_budgets: Vec<DeclaredScopedBudgetDef>,
    #[serde(default)]
    pub limits: Option<DeclaredLimitsDef>,
}

/// `tenants[].policy`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredModelPolicyDef {
    /// Required: `all` or `{only: [...]}`.
    #[serde(default)]
    pub access: Option<DeclaredAccess>,
    /// Patterns refused even when `access` grants them.
    #[serde(default)]
    pub deny: Vec<String>,
}

/// `tenants[].policy.access`: the string `all`, or a map with one key `only`.
#[derive(Debug, PartialEq, Eq)]
pub enum DeclaredAccess {
    All,
    Only(Vec<String>),
}

/// The `{only: [...]}` form of [`DeclaredAccess`].
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredOnlyAccess {
    pub only: Vec<String>,
}

impl<'de> Deserialize<'de> for DeclaredAccess {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Rust note: a `Visitor` lets one type accept two YAML shapes (a
        // scalar and a map) while keeping serde's error paths.
        struct AccessVisitor;

        impl<'de> Visitor<'de> for AccessVisitor {
            type Value = DeclaredAccess;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("`all` or a map `{only: [model patterns]}`")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value == "all" {
                    Ok(DeclaredAccess::All)
                } else {
                    Err(E::invalid_value(de::Unexpected::Str(value), &self))
                }
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                let body = DeclaredOnlyAccess::deserialize(MapAccessDeserializer::new(map))?;
                Ok(DeclaredAccess::Only(body.only))
            }
        }

        deserializer.deserialize_any(AccessVisitor)
    }
}

/// `tenants[].budget`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredBudgetDef {
    #[serde(default)]
    pub max_usd: Option<DeclaredAmount>,
    #[serde(default)]
    pub period: Option<DeclaredPeriod>,
    #[serde(default)]
    pub credential_source: Option<DeclaredCredentialSource>,
}

/// One entry in `tenants[].scoped_budgets`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredScopedBudgetDef {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub max_usd: Option<DeclaredAmount>,
    #[serde(default)]
    pub period: Option<DeclaredPeriod>,
    #[serde(default)]
    pub credential_source: Option<DeclaredCredentialSource>,
    #[serde(default)]
    pub models: Vec<String>,
    /// Names of entries in the top-level `providers` map.
    #[serde(default)]
    pub providers: Vec<String>,
    #[serde(default)]
    pub alert_at_percent: Vec<u32>,
}

/// `tenants[].limits`. An unset field sets no limit.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredLimitsDef {
    #[serde(default)]
    pub tokens_per_minute: Option<u64>,
    #[serde(default)]
    pub requests_per_minute: Option<u64>,
    #[serde(default)]
    pub tokens_per_day: Option<u64>,
    #[serde(default)]
    pub requests_per_day: Option<u64>,
    #[serde(default)]
    pub concurrent_streams: Option<u32>,
}

/// A budget period.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeclaredPeriod {
    Daily,
    Weekly,
    Monthly,
}

impl DeclaredPeriod {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DeclaredPeriod::Daily => "daily",
            DeclaredPeriod::Weekly => "weekly",
            DeclaredPeriod::Monthly => "monthly",
        }
    }
}

/// Whose provider credentials a budget covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeclaredCredentialSource {
    Platform,
    Tenant,
}

impl DeclaredCredentialSource {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DeclaredCredentialSource::Platform => "platform",
            DeclaredCredentialSource::Tenant => "tenant",
        }
    }
}

/// A `max_usd` value as written. A YAML float is kept as a marker so the
/// lowering can reject it at its dotted path: `12.5` may already have been
/// rounded by the YAML parser, and money must not be.
#[derive(Debug, PartialEq, Eq)]
pub enum DeclaredAmount {
    /// A quoted decimal string, or a negative integer (rejected later by the
    /// decimal grammar).
    Text(String),
    /// An unquoted non-negative integer.
    Integer(u64),
    /// An unquoted number with a fraction or exponent.
    Float,
}

impl<'de> Deserialize<'de> for DeclaredAmount {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct AmountVisitor;

        impl Visitor<'_> for AmountVisitor {
            type Value = DeclaredAmount;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a quoted decimal string such as \"500.00\", or an integer")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(DeclaredAmount::Text(value.to_owned()))
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(DeclaredAmount::Integer(value))
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(DeclaredAmount::Text(value.to_string()))
            }

            fn visit_f64<E: de::Error>(self, _value: f64) -> Result<Self::Value, E> {
                Ok(DeclaredAmount::Float)
            }
        }

        deserializer.deserialize_any(AmountVisitor)
    }
}
