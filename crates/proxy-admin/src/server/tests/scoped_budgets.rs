//! `PUT /tenants/{id}/scoped_budgets` refuses an invalid set whole, naming
//! the field and never echoing the rejected value, and `GET` reports what a
//! valid set stored.

use super::*;

/// A provider no config defines. No 400 may echo it back.
const REJECTED_PROVIDER: &str = "provider-SENTINEL-41c9";

fn stored(
    handle: &Arc<arc_swap::ArcSwap<proxy_control::control::ControlPlaneSnapshot>>,
) -> Vec<proxy_control::spend::ScopedBudget> {
    handle
        .load()
        .policies
        .get("tenant-a")
        .map(|p| p.scoped_budgets.to_vec())
        .unwrap_or_default()
}

#[tokio::test]
async fn an_invalid_scoped_budget_set_is_refused_whole_and_a_valid_one_is_stored() {
    let (factory_state, handle, _accumulator) =
        factory_state_with_control_plane_and_spend(Period::Monthly);
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;
    // `upstream` is the fixture snapshot's one cluster.
    let valid = r#"{"name":"ok","max_usd":"1.00","period":"daily","providers":["upstream"]}"#;
    let rejected_provider = format!(
        r#"{{"name":"x","max_usd":"1","period":"daily","providers":["{REJECTED_PROVIDER}"]}}"#
    );
    for (bad, names) in [
        (rejected_provider.as_str(), "budgets[1].providers[0]"),
        (
            r#"{"name":"Bad Name","max_usd":"1","period":"daily","models":["m"]}"#,
            "budgets[1].name",
        ),
        (
            r#"{"name":"ok","max_usd":"1","period":"daily","models":["m"]}"#,
            "duplicate `budgets[1].name`",
        ),
        (
            r#"{"name":"x","max_usd":"1","period":"daily"}"#,
            "`budgets[1]` names no models and no providers",
        ),
        (
            r#"{"name":"x","max_usd":"1","period":"daily","models":["*m"]}"#,
            "budgets[1].models[0]",
        ),
        (
            r#"{"name":"x","max_usd":"1","period":"daily","models":["m"],"alert_at_percent":[0]}"#,
            "budgets[1].alert_at_percent",
        ),
    ] {
        let (status, _, body) = request(
            addr,
            "PUT",
            "/tenants/tenant-a/scoped_budgets",
            Some(ADMIN_TOKEN),
            &format!(r#"{{"budgets":[{valid},{bad}]}}"#),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{names}: {body}");
        assert!(body.contains(names), "the 400 names {names}: {body}");
        assert!(!body.contains(REJECTED_PROVIDER), "no echo: {body}");
        assert!(stored(&handle).is_empty(), "{names}: nothing is stored");
    }

    let (status, _, body) = request(
        addr,
        "PUT",
        "/tenants/tenant-a/scoped_budgets",
        Some(ADMIN_TOKEN),
        &format!(r#"{{"budgets":[{valid}]}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let budgets = stored(&handle);
    assert_eq!(budgets.len(), 1);
    assert_eq!(budgets[0].providers, ["upstream"]);
    assert_eq!(budgets[0].max_micros, MicroUsd::from_micros(1_000_000));

    let (status, _, body) = request(
        addr,
        "GET",
        "/tenants/tenant-a/scoped_budgets",
        Some(ADMIN_TOKEN),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(value["budgets"][0]["name"], "ok", "{value}");
    assert_eq!(value["budgets"][0]["spend_micro_usd"], 0, "{value}");

    let (status, _, body) = request(
        addr,
        "PUT",
        "/tenants/tenant-a/scoped_budgets",
        Some(ADMIN_TOKEN),
        r#"{"budgets":[]}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert!(stored(&handle).is_empty(), "an empty set removes them");
}
