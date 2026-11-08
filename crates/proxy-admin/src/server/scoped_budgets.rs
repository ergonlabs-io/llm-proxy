//! `PUT` and `GET /tenants/{id}/scoped_budgets` (and the `/chains/{stat_prefix}/...` forms): a tenant's
//! budgets narrowed by model pattern and provider. See [`ScopedBudget`] for how they match.
//!
//! `PUT` replaces the whole set, so a write never merges with a stale copy another replica holds; `{"budgets":
//! []}` removes them all. Every field is checked before anything is stored, and a provider must name a cluster
//! this process knows (or a `--config` provider, see [`resolve_provider`]): a budget on a misspelled provider
//! would match nothing and cap nothing.

use std::collections::HashSet;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Response, StatusCode};
use proxy_control::auth::TenantId;
use proxy_control::control::ControlPlane;
use proxy_control::model_authz::ModelPattern;
use proxy_control::spend::{
    parse_micro_usd, scoped_spend_subject, utilization_percent, ScopedBudget, SpendAccumulator,
};
use proxy_credentials::CredentialSource;
use proxy_http::filter::SharedFactoryState;

use super::{
    bad_request, json, no_content, not_enforced, parse_json_body, read_api_schema_version,
    render_micro_usd, resolve_spend_shared, store_error_response, text, PeriodSpec,
};

/// The most scoped budgets one tenant may hold. Every request of the tenant walks them.
pub(super) const MAX_SCOPED_BUDGETS: usize = 32;

/// The most model patterns or providers one scoped budget may name.
const MAX_MATCHERS: usize = 64;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SetScopedBudgetsRequest {
    #[serde(
        default,
        rename = "schema_version",
        deserialize_with = "read_api_schema_version"
    )]
    _schema_version: (),
    budgets: Vec<ScopedBudgetSpec>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopedBudgetSpec {
    name: String,
    max_usd: String,
    period: PeriodSpec,
    /// `"platform"` (the default) or `"tenant"`; a plain string so an unknown value gets a fixed message rather
    /// than serde's, which would echo the input.
    #[serde(default)]
    credential_source: Option<String>,
    #[serde(default)]
    models: Vec<String>,
    #[serde(default)]
    providers: Vec<String>,
    #[serde(default)]
    alert_at_percent: Vec<u8>,
}

/// `PUT /tenants/{id}/scoped_budgets`. `known_clusters` is every cluster in the published config.
pub(super) fn handle_set_scoped_budgets(
    factory_state: &SharedFactoryState,
    stat_prefix: Option<&str>,
    control_plane: &ControlPlane,
    tenant: &str,
    body: &[u8],
    known_clusters: &HashSet<String>,
) -> Response<Full<Bytes>> {
    if tenant.is_empty() {
        return bad_request("tenant must not be empty");
    }
    let request: SetScopedBudgetsRequest = match parse_json_body(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let budgets = match budgets_from_specs(request.budgets, known_clusters) {
        Ok(budgets) => budgets,
        Err(message) => return bad_request(&message),
    };
    // A budget no spend filter reads is a cap that caps nothing; removing them is always allowed.
    if !budgets.is_empty() && resolve_spend_shared(factory_state, stat_prefix).is_none() {
        return not_enforced(
            "no listener chain runs llmproxy.spend_limit; scoped budgets would not be enforced",
        );
    }
    match control_plane.set_scoped_budgets(&TenantId::new(tenant), &budgets) {
        Ok(()) => {
            tracing::info!(
                endpoint = "/tenants/{id}/scoped_budgets",
                tenant,
                count = budgets.len(),
                "admin: replaced a tenant's scoped budgets"
            );
            no_content()
        }
        Err(err) => store_error_response("/tenants/{id}/scoped_budgets", err),
    }
}

/// Validates every spec, in order; the first failure is the 400. Messages name the field and the budget's index,
/// never the rejected value.
fn budgets_from_specs(
    specs: Vec<ScopedBudgetSpec>,
    known_clusters: &HashSet<String>,
) -> Result<Vec<ScopedBudget>, String> {
    if specs.len() > MAX_SCOPED_BUDGETS {
        return Err(format!(
            "at most {MAX_SCOPED_BUDGETS} scoped budgets per tenant"
        ));
    }
    let mut names = HashSet::new();
    let mut budgets = Vec::with_capacity(specs.len());
    for (i, spec) in specs.into_iter().enumerate() {
        let at = format!("budgets[{i}]");
        if !ScopedBudget::is_valid_name(&spec.name) {
            return Err(format!(
                "invalid `{at}.name`: 1 to {} characters of a-z, 0-9, `-` and `_`, starting with a letter or digit",
                ScopedBudget::MAX_NAME_LEN
            ));
        }
        if !names.insert(spec.name.clone()) {
            return Err(format!("duplicate `{at}.name`"));
        }
        let max_micros = parse_micro_usd(&spec.max_usd)
            .map_err(|err| format!("invalid `{at}.max_usd`: {err}"))?;
        let credential_source = match spec.credential_source.as_deref() {
            None | Some("platform") => CredentialSource::Platform,
            Some("tenant") => CredentialSource::Tenant,
            Some(_) => {
                return Err(format!(
                    "invalid `{at}.credential_source`: expected \"platform\" or \"tenant\""
                ))
            }
        };
        if spec.models.is_empty() && spec.providers.is_empty() {
            return Err(format!(
                "`{at}` names no models and no providers; a budget on all of a tenant's spend is \
                 PUT /tenants/{{id}}/budget"
            ));
        }
        if spec.models.len() > MAX_MATCHERS || spec.providers.len() > MAX_MATCHERS {
            return Err(format!(
                "`{at}` names more than {MAX_MATCHERS} models or providers"
            ));
        }
        if let Some(j) = spec.models.iter().position(|m| !ModelPattern::is_valid(m)) {
            return Err(format!(
                "invalid `{at}.models[{j}]`: an exact model name, or a prefix ending in one `*`"
            ));
        }
        let mut providers = Vec::with_capacity(spec.providers.len());
        for (j, provider) in spec.providers.iter().enumerate() {
            let Some(cluster) = resolve_provider(provider, known_clusters) else {
                return Err(format!(
                    "invalid `{at}.providers[{j}]`: neither a cluster nor a `providers` entry in \
                     this proxy's config"
                ));
            };
            if !providers.contains(&cluster) {
                providers.push(cluster);
            }
        }
        let mut alert_at_percent = spec.alert_at_percent;
        if alert_at_percent.iter().any(|p| !(1..=100).contains(p)) {
            return Err(format!(
                "invalid `{at}.alert_at_percent`: each level is 1 to 100"
            ));
        }
        alert_at_percent.sort_unstable();
        if alert_at_percent.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(format!("duplicate level in `{at}.alert_at_percent`"));
        }
        budgets.push(ScopedBudget {
            name: spec.name,
            max_micros,
            period: spec.period.into(),
            credential_source,
            models: spec.models.into_iter().map(ModelPattern::new).collect(),
            providers,
            alert_at_percent,
        });
    }
    Ok(budgets)
}

/// The cluster a `providers` entry names: the cluster of that exact name, or else the cluster the `--config`
/// dialect lowers its provider of that name to (`provider:<name>`). The stored budget keeps the cluster name,
/// which is what an attempt reports as dialled.
fn resolve_provider(provider: &str, known_clusters: &HashSet<String>) -> Option<String> {
    if known_clusters.contains(provider) {
        return Some(provider.to_owned());
    }
    let dialect = format!("provider:{provider}");
    known_clusters.contains(&dialect).then_some(dialect)
}

/// `GET /tenants/{id}/scoped_budgets`: each budget as stored, with this replica's live spend for its current
/// period. `null` spend fields when this chain runs no spend filter.
pub(super) fn handle_get_scoped_budgets(
    control_plane: &ControlPlane,
    accumulator: Option<std::sync::Arc<SpendAccumulator>>,
    tenant: &str,
) -> Response<Full<Bytes>> {
    if tenant.is_empty() {
        return bad_request("tenant must not be empty");
    }
    let Some(accumulator) = accumulator else {
        return text(
            StatusCode::SERVICE_UNAVAILABLE,
            "llmproxy.spend_limit is not configured on this chain, so there is no spend \
             accumulator to report from",
        );
    };
    let tenant_id = TenantId::new(tenant);
    let snapshot = control_plane.handle().load();
    let budgets = snapshot
        .policies
        .get(tenant)
        .map(|policy| std::sync::Arc::clone(&policy.scoped_budgets))
        .unwrap_or_default();
    let rendered: Vec<serde_json::Value> = budgets
        .iter()
        .map(|budget| {
            let period_key = budget.period.key_for_now();
            let (start, end) = budget.period.window_now();
            let report =
                accumulator.report(&scoped_spend_subject(&tenant_id, &budget.name), &period_key);
            let limit = budget.max_micros.as_micros();
            serde_json::json!({
                "name": budget.name,
                "max_usd": render_micro_usd(limit),
                "max_micro_usd": limit,
                "period": PeriodSpec::from(budget.period),
                "credential_source": budget.credential_source.as_str(),
                "models": budget.models.iter().map(ModelPattern::as_str).collect::<Vec<_>>(),
                "providers": budget.providers,
                "alert_at_percent": budget.alert_at_percent,
                "current_period": period_key.as_str(),
                "period_started_at": start.to_rfc3339(),
                "period_ends_at": end.to_rfc3339(),
                "spend_micro_usd": report.total_micros,
                "spend_usd": render_micro_usd(report.total_micros),
                // Saturating: in-flight requests can overrun a ceiling.
                "remaining_micro_usd": limit.saturating_sub(report.total_micros),
                "utilization_percent": utilization_percent(report.total_micros, limit),
            })
        })
        .collect();
    json(
        StatusCode::OK,
        &serde_json::json!({ "tenant": tenant, "budgets": rendered }),
    )
}
