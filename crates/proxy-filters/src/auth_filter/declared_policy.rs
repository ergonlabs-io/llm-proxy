//! `typed_config.declared_policy`: the tenants, model policies, budgets,
//! scoped budgets and limits the config declares. Parsed here into the
//! [`DeclaredPolicy`] the control plane reconciles into its store. Every
//! error names its full dotted path (AGENTS.md invariant 1).
//!
//! A scoped budget's providers are cluster names; whether each names a
//! configured cluster is checked across resources, where the cluster set is
//! known (`proxy_config::lower::validate_cross_resource`).

use std::collections::HashSet;

use prost_reflect::{DynamicMessage, Value};
use proxy_config::ConfigError;
use proxy_control::auth::TenantId;
use proxy_control::control::LimitPolicy;
use proxy_control::declared::{DeclaredPolicy, DeclaredTenant};
use proxy_control::model_authz::{ModelAccess, ModelPattern};
use proxy_control::spend::{
    parse_micro_usd, validate_scoped_budgets, Period, ScopedBudgetSpec, TenantBudget,
};
use proxy_credentials::CredentialSource;

use super::invalid;

const BASE: &str = "typed_config.declared_policy";

/// Longest declared tenant id, the same bound the dialect puts on
/// `auth.keys[].tenant`.
const MAX_TENANT_ID_BYTES: usize = 128;

/// `None` when the field is unset: the config declares nothing and the
/// store is left as it is.
pub(super) fn parse(config: &DynamicMessage) -> Result<Option<DeclaredPolicy>, ConfigError> {
    if !config.has_field_by_name("declared_policy") {
        return Ok(None);
    }
    let block = message(config, "declared_policy", BASE)?;
    let revision = block
        .get_field_by_name("revision")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if revision == 0 {
        return Err(invalid(
            format!("{BASE}.revision"),
            "is required and must be at least 1",
        ));
    }
    let mut seen = HashSet::new();
    let mut tenants = Vec::new();
    for (i, entry) in list(&block, "tenants").iter().enumerate() {
        let path = format!("{BASE}.tenants[{i}]");
        let entry = entry
            .as_message()
            .ok_or_else(|| invalid(&path, "must be a message"))?;
        let tenant = parse_tenant(entry, &path)?;
        if !seen.insert(tenant.tenant.as_str().to_owned()) {
            return Err(invalid(
                format!("{path}.id"),
                "duplicates an earlier tenant",
            ));
        }
        tenants.push(tenant);
    }
    Ok(Some(DeclaredPolicy::new(revision, tenants)))
}

fn parse_tenant(entry: &DynamicMessage, path: &str) -> Result<DeclaredTenant, ConfigError> {
    let id = string(entry, "id");
    if id.is_empty() {
        return Err(invalid(
            format!("{path}.id"),
            "is required and must not be empty",
        ));
    }
    if id.len() > MAX_TENANT_ID_BYTES || id.chars().any(char::is_control) {
        return Err(invalid(
            format!("{path}.id"),
            format!("must be at most {MAX_TENANT_ID_BYTES} bytes with no control characters"),
        ));
    }
    if proxy_observability::records::RESERVED_TENANT_IDS.contains(&id.as_str()) {
        return Err(invalid(format!("{path}.id"), "is a reserved tenant id"));
    }
    let policy = entry
        .has_field_by_name("policy")
        .then(|| parse_policy(&message(entry, "policy", path)?, &format!("{path}.policy")))
        .transpose()?;
    let budget = entry
        .has_field_by_name("budget")
        .then(|| parse_budget(&message(entry, "budget", path)?, &format!("{path}.budget")))
        .transpose()?;
    let scoped_budgets = parse_scoped_budgets(entry, path)?;
    let limits = entry
        .has_field_by_name("limits")
        .then(|| parse_limits(&message(entry, "limits", path)?, &format!("{path}.limits")))
        .transpose()?;
    Ok(DeclaredTenant {
        tenant: TenantId::new(id),
        policy,
        budget,
        scoped_budgets,
        limits,
    })
}

fn parse_policy(policy: &DynamicMessage, path: &str) -> Result<ModelAccess, ConfigError> {
    let patterns = |values: Vec<Value>, at: &str| -> Result<Vec<ModelPattern>, ConfigError> {
        values
            .iter()
            .enumerate()
            .map(|(j, value)| {
                let pattern = value.as_str().unwrap_or_default();
                if ModelPattern::is_valid(pattern) {
                    Ok(ModelPattern::new(pattern))
                } else {
                    Err(invalid(
                        format!("{at}[{j}]"),
                        "must be an exact model name or a prefix ending in one `*`",
                    ))
                }
            })
            .collect()
    };
    let access = if policy.has_field_by_name("all") {
        ModelAccess::All
    } else if policy.has_field_by_name("only") {
        let only = message(policy, "only", path)?;
        ModelAccess::Only(patterns(
            list(&only, "patterns"),
            &format!("{path}.only.patterns"),
        )?)
    } else {
        return Err(invalid(
            path,
            "must set exactly one of `all` and `only` (an empty `only` grants nothing)",
        ));
    };
    let deny = patterns(list(policy, "deny"), &format!("{path}.deny"))?;
    Ok(access.with_deny(deny))
}

fn parse_period(raw: &str, path: &str) -> Result<Period, ConfigError> {
    match raw {
        "daily" => Ok(Period::Daily),
        "weekly" => Ok(Period::Weekly),
        "monthly" => Ok(Period::Monthly),
        "" => Err(invalid(path, "is required: daily, weekly or monthly")),
        _ => Err(invalid(path, "must be daily, weekly or monthly")),
    }
}

fn parse_credential_source(raw: &str, path: &str) -> Result<CredentialSource, ConfigError> {
    match raw {
        "" | "platform" => Ok(CredentialSource::Platform),
        "tenant" => Ok(CredentialSource::Tenant),
        _ => Err(invalid(path, "must be platform or tenant")),
    }
}

fn parse_budget(budget: &DynamicMessage, path: &str) -> Result<TenantBudget, ConfigError> {
    let max_micros = parse_micro_usd(&string(budget, "max_usd"))
        .map_err(|err| invalid(format!("{path}.max_usd"), err.to_string()))?;
    Ok(TenantBudget {
        max_micros,
        period: parse_period(&string(budget, "period"), &format!("{path}.period"))?,
        credential_source: parse_credential_source(
            &string(budget, "credential_source"),
            &format!("{path}.credential_source"),
        )?,
    })
}

fn parse_scoped_budgets(
    entry: &DynamicMessage,
    path: &str,
) -> Result<Vec<proxy_control::spend::ScopedBudget>, ConfigError> {
    let mut specs = Vec::new();
    for (i, value) in list(entry, "scoped_budgets").iter().enumerate() {
        let at = format!("{path}.scoped_budgets[{i}]");
        let budget = value
            .as_message()
            .ok_or_else(|| invalid(&at, "must be a message"))?;
        let strings = |field: &str| -> Vec<String> {
            list(budget, field)
                .iter()
                .map(|v| v.as_str().unwrap_or_default().to_owned())
                .collect()
        };
        let credential_source = string(budget, "credential_source");
        specs.push(ScopedBudgetSpec {
            name: string(budget, "name"),
            max_usd: string(budget, "max_usd"),
            period: parse_period(&string(budget, "period"), &format!("{at}.period"))?,
            credential_source: (!credential_source.is_empty()).then_some(credential_source),
            models: strings("models"),
            providers: strings("providers"),
            alert_at_percent: list(budget, "alert_at_percent")
                .iter()
                .map(|v| v.as_u32().unwrap_or_default())
                .collect(),
        });
    }
    // The shared rules name a field as `<at(i)>.<field>`; the message is the
    // whole error, so it is reported at the list's own path.
    validate_scoped_budgets(
        specs,
        |i| format!("{path}.scoped_budgets[{i}]"),
        |provider| Some(provider.to_owned()),
    )
    .map_err(|reason| invalid(format!("{path}.scoped_budgets"), reason))
}

fn parse_limits(limits: &DynamicMessage, path: &str) -> Result<LimitPolicy, ConfigError> {
    let u64_field = |name: &str| {
        limits
            .has_field_by_name(name)
            .then(|| limits.get_field_by_name(name).and_then(|v| v.as_u64()))
            .flatten()
    };
    let policy = LimitPolicy {
        tokens_per_minute: u64_field("tokens_per_minute"),
        requests_per_minute: u64_field("requests_per_minute"),
        tokens_per_day: u64_field("tokens_per_day"),
        requests_per_day: u64_field("requests_per_day"),
        concurrent_streams: limits
            .has_field_by_name("concurrent_streams")
            .then(|| {
                limits
                    .get_field_by_name("concurrent_streams")
                    .and_then(|v| v.as_u32())
            })
            .flatten(),
    };
    if policy == LimitPolicy::default() {
        return Err(invalid(
            path,
            "sets no limit; set at least one field or remove the block",
        ));
    }
    Ok(policy)
}

fn message(
    parent: &DynamicMessage,
    field: &str,
    path: &str,
) -> Result<DynamicMessage, ConfigError> {
    parent
        .get_field_by_name(field)
        .and_then(|v| v.as_message().cloned())
        .ok_or_else(|| invalid(format!("{path}.{field}"), "must be a message"))
}

fn list(parent: &DynamicMessage, field: &str) -> Vec<Value> {
    parent
        .get_field_by_name(field)
        .and_then(|v| v.as_list().map(<[_]>::to_vec))
        .unwrap_or_default()
}

fn string(parent: &DynamicMessage, field: &str) -> String {
    parent
        .get_field_by_name(field)
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}
