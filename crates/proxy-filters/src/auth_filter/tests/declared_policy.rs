//! `typed_config.declared_policy` in Envoy mode: what the parser hands the
//! control plane, and the full dotted path of each refusal. The dialect's
//! own paths are pinned in `proxy-simple-config/tests/declared_policy.rs`.

use super::*;
use proxy_control::model_authz::ModelAccess;

fn config(declared: serde_json::Value) -> DynamicMessage {
    let descriptor = proxy_api::descriptor_pool()
        .get_message_by_name("llmproxy.filters.v0.Authentication")
        .expect("compiled into proxy-api");
    DynamicMessage::deserialize(
        descriptor,
        serde_json::json!({
            "hmac_secret": { "inline_string": "operator-hmac-secret" },
            "declared_policy": declared,
        }),
    )
    .expect("the fixture matches the proto")
}

fn refusal(declared: serde_json::Value) -> String {
    match parse_config(&config(declared)) {
        Ok(_) => panic!("the config must be refused"),
        Err(err) => err.to_string(),
    }
}

#[test]
fn a_declared_block_parses_into_sorted_tenants_with_every_row() {
    let parsed = parse_config(&config(serde_json::json!({
        "revision": 3,
        "tenants": [
            { "id": "zeta", "policy": { "all": {} } },
            {
                "id": "acme",
                "policy": { "only": { "patterns": ["gpt-4o*"] }, "deny": ["gpt-4o-mini"] },
                "budget": { "max_usd": "12.5", "period": "monthly", "credential_source": "tenant" },
                "scoped_budgets": [{ "name": "cap", "max_usd": "1", "period": "daily",
                                     "providers": ["openai"], "alert_at_percent": [80, 50] }],
                "limits": { "requests_per_minute": 0 }
            }
        ]
    })))
    .expect("a valid block parses");
    let declared = parsed.declared.expect("the block is declared");
    assert_eq!(declared.revision, 3);
    let ids: Vec<&str> = declared.tenants.iter().map(|t| t.tenant.as_str()).collect();
    assert_eq!(ids, ["acme", "zeta"]);
    let acme = &declared.tenants[0];
    assert_eq!(
        acme.budget
            .map(|b| (b.max_micros.as_micros(), b.credential_source)),
        Some((12_500_000, proxy_credentials::CredentialSource::Tenant))
    );
    assert_eq!(acme.scoped_budgets[0].providers, ["openai"]);
    assert_eq!(acme.scoped_budgets[0].alert_at_percent, [50, 80]);
    assert_eq!(
        acme.limits.map(|l| l.requests_per_minute),
        Some(Some(0)),
        "an explicit zero is a limit, not an absent one"
    );
    assert!(matches!(declared.tenants[1].policy, Some(ModelAccess::All)));
}

#[test]
fn each_refusal_names_its_full_dotted_path() {
    let base = "typed_config.declared_policy";
    for (declared, path) in [
        (
            serde_json::json!({ "tenants": [] }),
            format!("{base}.revision"),
        ),
        (
            serde_json::json!({ "revision": 1, "tenants": [{ "id": "a" }, { "id": "a" }] }),
            format!("{base}.tenants[1].id"),
        ),
        (
            serde_json::json!({ "revision": 1, "tenants": [{ "id": "default" }] }),
            format!("{base}.tenants[0].id"),
        ),
        (
            serde_json::json!({ "revision": 1, "tenants": [{ "id": "a", "policy": { "deny": ["x*y"] } }] }),
            format!("{base}.tenants[0].policy"),
        ),
        (
            serde_json::json!({ "revision": 1, "tenants": [{ "id": "a",
                "policy": { "only": { "patterns": ["ok", "x*y"] } } }] }),
            format!("{base}.tenants[0].policy.only.patterns[1]"),
        ),
        (
            serde_json::json!({ "revision": 1, "tenants": [{ "id": "a",
                "budget": { "max_usd": "1.1234567", "period": "daily" } }] }),
            format!("{base}.tenants[0].budget.max_usd"),
        ),
        (
            serde_json::json!({ "revision": 1, "tenants": [{ "id": "a",
                "budget": { "max_usd": "1", "period": "hourly" } }] }),
            format!("{base}.tenants[0].budget.period"),
        ),
        (
            serde_json::json!({ "revision": 1, "tenants": [{ "id": "a", "limits": {} }] }),
            format!("{base}.tenants[0].limits"),
        ),
        (
            serde_json::json!({ "revision": 1, "tenants": [{ "id": "a",
                "scoped_budgets": [{ "name": "Bad Name", "max_usd": "1", "period": "daily",
                                     "models": ["m"] }] }] }),
            format!("{base}.tenants[0].scoped_budgets[0].name"),
        ),
    ] {
        let message = refusal(declared.clone());
        assert!(
            message.contains(&path),
            "{declared}: the refusal must name {path}: {message}"
        );
    }
}
