//! `auth.jwt`: JWT/OIDC providers (ADR-0014). Each entry lowers to one
//! `llmproxy.filters.v0.Authentication.jwt_providers` entry.
//!
//! Rust note: required fields are `Option`s, as on [`super::TenantCredentials`],
//! so a missing one is reported by `lower.rs` at its full dotted path
//! (`auth.jwt[0].tenant.claim`) rather than by serde naming only the struct.

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

use super::SimpleDuration;

/// One entry in `auth.jwt`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtProviderDef {
    /// The token's `iss` must equal this. Required (ADR-0014 D1).
    #[serde(default)]
    pub issuer: Option<String>,
    /// The token's `aud` must contain this. Required (ADR-0014 D2).
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub jwks: Option<JwtJwksDef>,
    #[serde(default)]
    pub tenant: Option<JwtTenantDef>,
    #[serde(default)]
    pub user: Option<JwtUserDef>,
    /// Verified claims that set chargeback tags. Absent means none.
    #[serde(default)]
    pub claim_tags: Vec<JwtClaimTagDef>,
}

/// One entry in `auth.jwt[i].claim_tags`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtClaimTagDef {
    #[serde(default)]
    pub claim: Option<String>,
    #[serde(default)]
    pub tag: Option<String>,
}

/// `auth.jwt[i].jwks`: exactly one of `discovery_url` / `keys`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtJwksDef {
    #[serde(default)]
    pub discovery_url: Option<String>,
    /// Only with `discovery_url`. Whole seconds.
    #[serde(default)]
    pub refresh_interval: Option<SimpleDuration>,
    /// Only with `discovery_url`. PEM bundle trusted instead of system roots.
    #[serde(default)]
    pub trusted_ca_file: Option<String>,
    #[serde(default)]
    pub keys: Option<Vec<JwtKeyDef>>,
}

/// One RSA public key in `auth.jwt[i].jwks.keys`, in the JWKS document's own
/// base64url encoding.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtKeyDef {
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
}

/// `auth.jwt[i].tenant`: which claim names the tenant, and the allow-list
/// mapping its values to llm-proxy tenants.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtTenantDef {
    #[serde(default)]
    pub claim: Option<String>,
    /// Claim value -> tenant. `deserialize_with` rejects a duplicate claim
    /// value rather than keeping the last one.
    #[serde(default, deserialize_with = "deserialize_tenant_values")]
    pub values: Option<BTreeMap<String, String>>,
}

/// `auth.jwt[i].user`: which claim names the user.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtUserDef {
    #[serde(default)]
    pub claim: Option<String>,
}

/// Deserializes `auth.jwt[i].tenant.values`, erroring on a literal duplicate
/// claim value, for the same reason as `auto.tenants`.
fn deserialize_tenant_values<'de, D>(
    deserializer: D,
) -> Result<Option<BTreeMap<String, String>>, D::Error>
where
    D: Deserializer<'de>,
{
    struct TenantValuesVisitor;

    impl<'de> Visitor<'de> for TenantValuesVisitor {
        type Value = BTreeMap<String, String>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a map of claim value -> tenant")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut out = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, String>()? {
                if out.insert(key.clone(), value).is_some() {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate `tenant.values` entry `{key}`"
                    )));
                }
            }
            Ok(out)
        }
    }

    deserializer.deserialize_map(TenantValuesVisitor).map(Some)
}
