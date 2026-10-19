//! `auth.jwt` -> `llmproxy.filters.v0.Authentication.jwt_providers`
//! (ADR-0014). Lowering only: every check here is one the filter either
//! makes again on the proto, or a dialect rule stricter than Envoy mode
//! (ADR-0014 D1-D7). Errors name dialect paths (`auth.jwt[0].tenant.claim`),
//! never the proto's `typed_config.jwt_providers[0]...`.

use std::collections::HashMap;

use proxy_config::{ConfigError, ConfigWarning};
use serde_json::{json, Map, Value};

use super::{warning, MAX_PRINCIPAL_ID_BYTES};
use crate::model::{Auth, JwtJwksDef, JwtProviderDef, SimpleDuration};

/// Bytes a lowered user id must leave for the subject claim: one UUID, the
/// length of Entra's `oid`. A longer subject is refused in request records
/// (over [`MAX_PRINCIPAL_ID_BYTES`]), so a prefix that leaves less than this
/// would lose most users' usage records (ADR-0014 decision 2).
const MIN_SUBJECT_BYTES: usize = 36;

/// The tenant a missing tenant normalizes to (AGENTS.md "Policy Domains").
/// A JWT must never be admitted as it (ADR-0014 decision 3).
const RESERVED_DEFAULT_TENANT: &str = "default";

const JWT_PLATFORM_MODE_WARNING: &str =
    "JWT callers always use the operator's provider keys: a tenant that stored its own \
     provider credentials (auth.tenant_credentials) has them applied to virtual-key \
     requests only, and its JWT requests are charged as platform spend (ADR-0014)";

fn invalid(field_path: impl Into<String>, reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidValue {
        field_path: field_path.into(),
        reason: reason.into(),
    }
}

/// A required, non-empty string field.
fn required<'a>(value: Option<&'a String>, path: &str) -> Result<&'a str, ConfigError> {
    match value.map(String::as_str) {
        Some(v) if !v.is_empty() => Ok(v),
        Some(_) => Err(invalid(path, "must not be empty")),
        None => Err(invalid(path, "is required")),
    }
}

/// Lowers every `auth.jwt` entry, in order. An empty list lowers to no
/// providers, so configs without `jwt` lower byte-identically.
pub(super) fn lower_jwt_providers(
    auth: &Auth,
    warnings: &mut Vec<ConfigWarning>,
) -> Result<Vec<Value>, ConfigError> {
    let mut seen_issuers: HashMap<&str, usize> = HashMap::new();
    let mut out = Vec::with_capacity(auth.jwt.len());
    for (i, provider) in auth.jwt.iter().enumerate() {
        let base = format!("auth.jwt[{i}]");
        let issuer = required(provider.issuer.as_ref(), &format!("{base}.issuer"))?;
        // The filter routes a token to the first provider whose issuer
        // matches its `iss`, so a second entry with the same issuer would
        // never see a token (ADR-0014 D7).
        if let Some(&first) = seen_issuers.get(issuer) {
            return Err(invalid(
                format!("{base}.issuer"),
                format!(
                    "duplicate `issuer`; already used at index {first}, which claims every \
                     token from this issuer"
                ),
            ));
        }
        seen_issuers.insert(issuer, i);
        out.push(lower_provider(provider, issuer, &base)?);
    }
    if !auth.jwt.is_empty() && auth.tenant_credentials.is_some() {
        warnings.push(warning("auth.jwt", JWT_PLATFORM_MODE_WARNING));
    }
    Ok(out)
}

fn lower_provider(
    provider: &JwtProviderDef,
    issuer: &str,
    base: &str,
) -> Result<Value, ConfigError> {
    let audience = required(provider.audience.as_ref(), &format!("{base}.audience"))?;

    let tenant = provider
        .tenant
        .as_ref()
        .ok_or_else(|| invalid(format!("{base}.tenant"), "is required"))?;
    let tenant_claim = required(tenant.claim.as_ref(), &format!("{base}.tenant.claim"))?;
    let values_path = format!("{base}.tenant.values");
    let values = match &tenant.values {
        Some(values) if !values.is_empty() => values,
        // ADR-0014 D4: an empty map would make the filter use the claim
        // value as the tenant, letting the IdP name any tenant.
        _ => {
            return Err(invalid(
                &values_path,
                "is required and must map at least one claim value to a tenant; the dialect \
                 never uses a claim value as a tenant name directly",
            ))
        }
    };
    // `jwt:<issuer>:<tenant>:` precedes the subject in the user id.
    let max_tenant_bytes =
        MAX_PRINCIPAL_ID_BYTES.saturating_sub(MIN_SUBJECT_BYTES + "jwt:".len() + issuer.len() + 2);
    let mut tenant_values = Map::new();
    for (claim_value, target) in values {
        if claim_value.is_empty() {
            return Err(invalid(&values_path, "a claim value must not be empty"));
        }
        let entry_path = format!("{values_path}.{claim_value}");
        if target.is_empty() {
            return Err(invalid(&entry_path, "must not be empty"));
        }
        if target == RESERVED_DEFAULT_TENANT {
            return Err(invalid(
                &entry_path,
                "must not be `default`: that tenant is reserved for unauthenticated traffic, \
                 and a JWT is never admitted as it",
            ));
        }
        if target.contains(':') {
            return Err(invalid(
                &entry_path,
                "must not contain `:`; the user id joins issuer, tenant and subject with `:`, \
                 so two tenants could share one user id",
            ));
        }
        if target.len() > max_tenant_bytes {
            return Err(invalid(
                &entry_path,
                format!(
                    "is {} bytes; with this issuer a tenant may be at most {max_tenant_bytes} \
                     bytes, so the user id `jwt:<issuer>:<tenant>:<subject>` keeps \
                     {MIN_SUBJECT_BYTES} bytes for the subject within the \
                     {MAX_PRINCIPAL_ID_BYTES}-byte limit",
                    target.len()
                ),
            ));
        }
        tenant_values.insert(claim_value.clone(), json!(target));
    }

    let user = provider
        .user
        .as_ref()
        .ok_or_else(|| invalid(format!("{base}.user"), "is required"))?;
    let subject_claim = required(user.claim.as_ref(), &format!("{base}.user.claim"))?;

    let jwks = provider
        .jwks
        .as_ref()
        .ok_or_else(|| invalid(format!("{base}.jwks"), "is required"))?;

    let mut lowered = json!({
        "issuer": issuer,
        "audience": audience,
        "tenant_claim": tenant_claim,
        "tenant_values": tenant_values,
        "subject_claim": subject_claim,
    });
    lower_jwks(jwks, &format!("{base}.jwks"), &mut lowered)?;
    Ok(lowered)
}

fn lower_jwks(jwks: &JwtJwksDef, base: &str, lowered: &mut Value) -> Result<(), ConfigError> {
    match (&jwks.discovery_url, &jwks.keys) {
        (Some(url), None) => {
            // Same rule the filter applies: JWKS over plaintext lets anyone
            // on the path mint tokens.
            let host = url.strip_prefix("https://").unwrap_or("");
            if host.is_empty() || host.starts_with('/') {
                return Err(invalid(
                    format!("{base}.discovery_url"),
                    "must be an `https` URL with a host",
                ));
            }
            lowered["discovery_url"] = json!(url);
            if let Some(SimpleDuration(interval)) = jwks.refresh_interval {
                let secs = interval.as_secs();
                if interval.subsec_nanos() != 0 || secs == 0 || secs > u64::from(u32::MAX) {
                    return Err(invalid(
                        format!("{base}.refresh_interval"),
                        "must be whole seconds and at least 1s",
                    ));
                }
                lowered["refresh_interval_seconds"] = json!(secs);
            }
            if let Some(file) = &jwks.trusted_ca_file {
                // Read once to fail at load with the dialect path; the
                // filter reads the file again itself.
                let contents = std::fs::read_to_string(file).map_err(|e| ConfigError::Io {
                    path: file.clone(),
                    reason: e.to_string(),
                })?;
                if !contents.contains("-----BEGIN CERTIFICATE-----") {
                    return Err(invalid(
                        format!("{base}.trusted_ca_file"),
                        "must be a PEM bundle with at least one certificate",
                    ));
                }
                lowered["trusted_ca"] = json!({ "filename": file });
            }
        }
        (None, Some(keys)) => {
            for (field, set) in [
                ("refresh_interval", jwks.refresh_interval.is_some()),
                ("trusted_ca_file", jwks.trusted_ca_file.is_some()),
            ] {
                if set {
                    return Err(invalid(
                        format!("{base}.{field}"),
                        "only applies with `discovery_url`; static `keys` are never fetched",
                    ));
                }
            }
            if keys.is_empty() {
                return Err(invalid(
                    format!("{base}.keys"),
                    "must contain at least one key (a provider with no keys verifies nothing)",
                ));
            }
            let mut seen_kids: HashMap<&str, usize> = HashMap::new();
            let mut lowered_keys = Vec::with_capacity(keys.len());
            for (j, key) in keys.iter().enumerate() {
                let key_base = format!("{base}.keys[{j}]");
                let kid = required(key.kid.as_ref(), &format!("{key_base}.kid"))?;
                if let Some(&first) = seen_kids.get(kid) {
                    return Err(invalid(
                        format!("{key_base}.kid"),
                        format!("duplicate `kid`; already used at index {first}"),
                    ));
                }
                seen_kids.insert(kid, j);
                let n = required(key.n.as_ref(), &format!("{key_base}.n"))?;
                let e = required(key.e.as_ref(), &format!("{key_base}.e"))?;
                validate_base64url(n, &format!("{key_base}.n"))?;
                validate_base64url(e, &format!("{key_base}.e"))?;
                lowered_keys.push(json!({ "kid": kid, "n": n, "e": e }));
            }
            lowered["keys"] = json!(lowered_keys);
        }
        (Some(_), Some(_)) => {
            return Err(invalid(base, "set either discovery_url or keys, not both"))
        }
        (None, None) => return Err(invalid(base, "set either discovery_url or keys")),
    }
    Ok(())
}

/// The shape the filter's decoder accepts: base64url (RFC 4648 §5) without
/// padding. A length of 1 mod 4 never decodes. Checked here so the error
/// names the dialect path.
fn validate_base64url(value: &str, path: &str) -> Result<(), ConfigError> {
    let alphabet = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    if !value.chars().all(alphabet) || value.len() % 4 == 1 {
        return Err(invalid(path, "must be valid base64url without padding"));
    }
    Ok(())
}
