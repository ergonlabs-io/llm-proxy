//! `auth.declared_policy` -> `Authentication.declared_policy`.
//!
//! The control plane checks the same rules again on the proto; they are
//! repeated here so errors name dialect paths, because this crate does not
//! depend on `proxy-control`. Each rule names its owner below.

use std::collections::{HashMap, HashSet};

use proxy_config::ConfigError;
use serde_json::{json, Map, Value};

use super::MAX_PRINCIPAL_ID_BYTES;
use crate::model::{
    Auth, DeclaredAccess, DeclaredAmount, DeclaredBudgetDef, DeclaredCredentialSource,
    DeclaredLimitsDef, DeclaredModelPolicyDef, DeclaredPeriod, DeclaredPolicyDef,
    DeclaredScopedBudgetDef, DeclaredTenantDef, SimpleConfig,
};

/// The tenant ids request records reserve (`default` for traffic with no
/// tenant, `unauthenticated` for refused requests); the store refuses them,
/// so they are never declared. Mirrors
/// `proxy_observability::records::RESERVED_TENANT_IDS`.
const RESERVED_TENANTS: [&str; 2] = ["default", "unauthenticated"];
/// Most scoped budgets on one tenant, as the control plane allows.
const MAX_SCOPED_BUDGETS: usize = 32;
/// Most model patterns, and most providers, on one scoped budget.
const MAX_SCOPE_ENTRIES: usize = 64;
/// Longest scoped-budget name; see `ScopedBudget::is_valid_name` below.
const MAX_NAME_LEN: usize = 64;

fn invalid(field_path: impl Into<String>, reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidValue {
        field_path: field_path.into(),
        reason: reason.into(),
    }
}

pub(super) fn lower(
    config: &SimpleConfig,
    auth: &Auth,
    declared: &DeclaredPolicyDef,
) -> Result<Value, ConfigError> {
    const PATH: &str = "auth.declared_policy";
    let revision = match declared.revision {
        Some(r) if r >= 1 => r,
        Some(_) => return Err(invalid(format!("{PATH}.revision"), "must be at least 1")),
        None => {
            return Err(invalid(
                format!("{PATH}.revision"),
                "is required: an integer of at least 1 that you raise on every edit, so a \
                 replica still on an older file cannot undo a newer one",
            ))
        }
    };

    // Rust note: the map remembers the first index of each id so the error
    // can name the SECOND (offending) entry.
    let mut seen: HashMap<&str, usize> = HashMap::new();
    let mut tenants = Vec::with_capacity(declared.tenants.len());
    for (i, tenant) in declared.tenants.iter().enumerate() {
        let path = format!("{PATH}.tenants[{i}]");
        tenants.push(lower_tenant(config, auth, tenant, &path, &mut seen, i)?);
    }
    Ok(json!({ "revision": revision, "tenants": tenants }))
}

fn lower_tenant<'a>(
    config: &SimpleConfig,
    auth: &Auth,
    tenant: &'a DeclaredTenantDef,
    path: &str,
    seen: &mut HashMap<&'a str, usize>,
    index: usize,
) -> Result<Value, ConfigError> {
    let id_path = format!("{path}.id");
    let Some(id) = tenant.id.as_deref() else {
        return Err(invalid(id_path, "is required"));
    };
    check_tenant_id(id, &id_path)?;
    if let Some(&first) = seen.get(id) {
        return Err(invalid(
            id_path,
            format!("duplicate tenant `{id}`; already declared at index {first}"),
        ));
    }
    seen.insert(id, index);

    let mut out = Map::new();
    out.insert("id".into(), json!(id));

    if let Some(policy) = &tenant.policy {
        let at = format!("{path}.policy");
        require_enforced(auth.enforce.model_policy, "model_policy", &at)?;
        out.insert("policy".into(), lower_policy(policy, &at)?);
    }
    if let Some(budget) = &tenant.budget {
        let at = format!("{path}.budget");
        require_enforced(auth.enforce.spend, "spend", &at)?;
        out.insert("budget".into(), lower_budget(budget, &at)?);
    }
    if !tenant.scoped_budgets.is_empty() {
        let at = format!("{path}.scoped_budgets");
        require_enforced(auth.enforce.spend, "spend", &at)?;
        out.insert(
            "scoped_budgets".into(),
            lower_scoped_budgets(config, &tenant.scoped_budgets, &at)?,
        );
    }
    if let Some(limits) = &tenant.limits {
        let at = format!("{path}.limits");
        require_enforced(auth.enforce.limits, "limits", &at)?;
        out.insert("limits".into(), lower_limits(limits, &at)?);
    }
    Ok(Value::Object(out))
}

/// A declared row is stored but never read when its control is switched off.
fn require_enforced(enforced: bool, toggle: &str, path: &str) -> Result<(), ConfigError> {
    if enforced {
        Ok(())
    } else {
        Err(invalid(
            path,
            format!(
                "`auth.enforce.{toggle}` is false, so this row would not be enforced; remove \
                 it or turn the control on"
            ),
        ))
    }
}

fn check_tenant_id(id: &str, path: &str) -> Result<(), ConfigError> {
    if id.is_empty() {
        return Err(invalid(path, "must not be empty"));
    }
    if RESERVED_TENANTS.contains(&id) {
        return Err(invalid(
            path,
            format!("`{id}` is a reserved tenant id and cannot be declared"),
        ));
    }
    if id.chars().any(|c| c.is_ascii_control()) {
        return Err(invalid(path, "must not contain control characters"));
    }
    if id.len() > MAX_PRINCIPAL_ID_BYTES {
        return Err(invalid(
            path,
            format!(
                "is {} bytes; the maximum is {MAX_PRINCIPAL_ID_BYTES}",
                id.len()
            ),
        ));
    }
    Ok(())
}

/// Same rule as `proxy_control::model_authz::ModelPattern::is_valid`: not
/// empty, and either no `*` or exactly one, at the end.
fn check_pattern(pattern: &str, path: &str) -> Result<(), ConfigError> {
    let stars = pattern.matches('*').count();
    if !pattern.is_empty() && (stars == 0 || (stars == 1 && pattern.ends_with('*'))) {
        Ok(())
    } else {
        Err(invalid(
            path,
            format!("model pattern `{pattern}` must be a model name or a prefix ending in one `*`"),
        ))
    }
}

fn check_patterns(patterns: &[String], path: &str) -> Result<(), ConfigError> {
    for (j, pattern) in patterns.iter().enumerate() {
        check_pattern(pattern, &format!("{path}[{j}]"))?;
    }
    Ok(())
}

fn lower_policy(policy: &DeclaredModelPolicyDef, path: &str) -> Result<Value, ConfigError> {
    let mut out = Map::new();
    match &policy.access {
        None => {
            return Err(invalid(
                format!("{path}.access"),
                "is required: `all` or `{only: [model patterns]}`",
            ))
        }
        Some(DeclaredAccess::All) => {
            out.insert("all".into(), json!({}));
        }
        Some(DeclaredAccess::Only(patterns)) => {
            check_patterns(patterns, &format!("{path}.access.only"))?;
            out.insert("only".into(), json!({ "patterns": patterns }));
        }
    }
    check_patterns(&policy.deny, &format!("{path}.deny"))?;
    if !policy.deny.is_empty() {
        out.insert("deny".into(), json!(policy.deny));
    }
    Ok(Value::Object(out))
}

/// Same grammar as `proxy_control::spend::parse_micro_usd`: digits, then an
/// optional `.` and 1 to 6 digits, no sign, and the micro-dollar value fits a
/// `u64`. Returns the amount as the decimal string the proto carries.
fn lower_amount(amount: Option<&DeclaredAmount>, path: &str) -> Result<String, ConfigError> {
    let text = match amount {
        None => return Err(invalid(path, "is required, for example \"500.00\"")),
        Some(DeclaredAmount::Float) => {
            return Err(invalid(
                path,
                "is a YAML number with a fraction; quote it as a string, for example \
                 \"12.50\", so no digit is lost to floating point",
            ))
        }
        Some(DeclaredAmount::Integer(n)) => n.to_string(),
        Some(DeclaredAmount::Text(text)) => text.clone(),
    };
    let (whole, frac) = text.split_once('.').unwrap_or((&text, ""));
    let digits = |part: &str| part.bytes().all(|b| b.is_ascii_digit());
    let well_formed = !whole.is_empty()
        && digits(whole)
        && digits(frac)
        && frac.len() <= 6
        && (!frac.is_empty() || !text.contains('.'));
    let fits = well_formed
        && whole.parse::<u64>().ok().is_some_and(|w| {
            let micros = format!("{frac:0<6}").parse::<u64>().unwrap_or(u64::MAX);
            w.checked_mul(1_000_000)
                .and_then(|m| m.checked_add(micros))
                .is_some()
        });
    if fits {
        Ok(text)
    } else {
        Err(invalid(
            path,
            format!(
                "`{text}` is not a USD amount: use digits with at most 6 decimal places, no \
                 sign, for example \"500.00\""
            ),
        ))
    }
}

fn lower_period(period: Option<DeclaredPeriod>, path: &str) -> Result<&'static str, ConfigError> {
    period
        .map(DeclaredPeriod::as_str)
        .ok_or_else(|| invalid(path, "is required: `daily`, `weekly` or `monthly`"))
}

fn lower_budget(budget: &DeclaredBudgetDef, path: &str) -> Result<Value, ConfigError> {
    let mut out = Map::new();
    out.insert(
        "max_usd".into(),
        json!(lower_amount(
            budget.max_usd.as_ref(),
            &format!("{path}.max_usd")
        )?),
    );
    out.insert(
        "period".into(),
        json!(lower_period(budget.period, &format!("{path}.period"))?),
    );
    if let Some(source) = budget.credential_source {
        out.insert("credential_source".into(), json!(source.as_str()));
    }
    Ok(Value::Object(out))
}

/// Same rule as `proxy_control::spend::ScopedBudget::is_valid_name`: 1 to 64
/// bytes of `a-z`, `0-9`, `-` and `_`, starting with a letter or digit.
fn is_valid_scope_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

fn lower_scoped_budgets(
    config: &SimpleConfig,
    budgets: &[DeclaredScopedBudgetDef],
    path: &str,
) -> Result<Value, ConfigError> {
    if budgets.len() > MAX_SCOPED_BUDGETS {
        return Err(invalid(
            path,
            format!(
                "has {} entries; the maximum is {MAX_SCOPED_BUDGETS} per tenant",
                budgets.len()
            ),
        ));
    }
    let mut names: HashMap<&str, usize> = HashMap::new();
    let mut out = Vec::with_capacity(budgets.len());
    for (i, budget) in budgets.iter().enumerate() {
        let at = format!("{path}[{i}]");
        out.push(lower_scoped_budget(config, budget, &at, &mut names, i)?);
    }
    Ok(Value::Array(out))
}

fn lower_scoped_budget<'a>(
    config: &SimpleConfig,
    budget: &'a DeclaredScopedBudgetDef,
    path: &str,
    names: &mut HashMap<&'a str, usize>,
    index: usize,
) -> Result<Value, ConfigError> {
    let name_path = format!("{path}.name");
    let Some(name) = budget.name.as_deref() else {
        return Err(invalid(name_path, "is required"));
    };
    if !is_valid_scope_name(name) {
        return Err(invalid(
            name_path,
            format!(
                "`{name}` must be 1 to {MAX_NAME_LEN} bytes of a-z, 0-9, `-` and `_`, starting \
                 with a letter or digit"
            ),
        ));
    }
    if let Some(&first) = names.get(name) {
        return Err(invalid(
            name_path,
            format!("duplicate name `{name}`; already used at index {first}"),
        ));
    }
    names.insert(name, index);

    let max_usd = lower_amount(budget.max_usd.as_ref(), &format!("{path}.max_usd"))?;
    let period = lower_period(budget.period, &format!("{path}.period"))?;

    if budget.models.is_empty() && budget.providers.is_empty() {
        return Err(invalid(
            path,
            "needs at least one of `models` and `providers`, or it would cover nothing",
        ));
    }
    for (field, len) in [
        ("models", budget.models.len()),
        ("providers", budget.providers.len()),
    ] {
        if len > MAX_SCOPE_ENTRIES {
            return Err(invalid(
                format!("{path}.{field}"),
                format!("has {len} entries; the maximum is {MAX_SCOPE_ENTRIES}"),
            ));
        }
    }
    check_patterns(&budget.models, &format!("{path}.models"))?;

    let mut clusters: Vec<String> = Vec::new();
    for (j, provider) in budget.providers.iter().enumerate() {
        if !config.providers.contains_key(provider) {
            return Err(invalid(
                format!("{path}.providers[{j}]"),
                format!("`{provider}` is not an entry in the top-level `providers` map"),
            ));
        }
        let cluster = format!("provider:{provider}");
        if !clusters.contains(&cluster) {
            clusters.push(cluster);
        }
    }

    let mut levels = HashSet::new();
    for (k, level) in budget.alert_at_percent.iter().enumerate() {
        let at = format!("{path}.alert_at_percent[{k}]");
        if !(1..=100).contains(level) {
            return Err(invalid(at, format!("{level} must be from 1 to 100")));
        }
        if !levels.insert(level) {
            return Err(invalid(at, format!("duplicate alert level {level}")));
        }
    }

    let mut out = Map::new();
    out.insert("name".into(), json!(name));
    out.insert("max_usd".into(), json!(max_usd));
    out.insert("period".into(), json!(period));
    if let Some(source) = budget.credential_source {
        out.insert(
            "credential_source".into(),
            json!(DeclaredCredentialSource::as_str(source)),
        );
    }
    if !budget.models.is_empty() {
        out.insert("models".into(), json!(budget.models));
    }
    if !clusters.is_empty() {
        out.insert("providers".into(), json!(clusters));
    }
    if !budget.alert_at_percent.is_empty() {
        out.insert("alert_at_percent".into(), json!(budget.alert_at_percent));
    }
    Ok(Value::Object(out))
}

fn lower_limits(limits: &DeclaredLimitsDef, path: &str) -> Result<Value, ConfigError> {
    let mut out = Map::new();
    let u64_fields = [
        ("tokens_per_minute", limits.tokens_per_minute),
        ("requests_per_minute", limits.requests_per_minute),
        ("tokens_per_day", limits.tokens_per_day),
        ("requests_per_day", limits.requests_per_day),
    ];
    for (field, value) in u64_fields {
        if let Some(value) = value {
            out.insert(field.into(), json!(value));
        }
    }
    if let Some(value) = limits.concurrent_streams {
        out.insert("concurrent_streams".into(), json!(value));
    }
    if out.is_empty() {
        return Err(invalid(
            path,
            "sets no limit; set at least one field, or remove the `limits` block",
        ));
    }
    Ok(Value::Object(out))
}
