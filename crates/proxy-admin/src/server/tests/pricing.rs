//! `PUT /pricing` and `GET /pricing`, driven over a real admin socket.
//!
//! The chain's rate card registry comes from the real usage filter factory, and
//! a chain with a store gets a real [`ControlPlane`] over a real redb file, so
//! these exercise the same wiring a running proxy has.

use super::*;
use crate::server::{MAX_ADMIN_BODY_BYTES, MAX_PRICING_BODY_BYTES};
use proxy_control::control::RedbControlPlaneStore;
use proxy_filters::usage_filter::UsageFilterFactory;
use proxy_http::filter::{FactoryContext, HttpFilterFactory};

const CHAIN: &str = "priced-chain";
const SCOPE: &str = "listener 'priced' filter_chains[0]";

fn card(label: &str, input: u64, effective_from: &str) -> serde_json::Value {
    serde_json::json!({
        "price_list": {
            "version": label,
            "effective_from": effective_from,
            "entries": [{
                "provider_type": "openai",
                "model": "gpt-5",
                "tier_mode": "whole_request",
                "tiers": [{
                    "input_nanodollars_per_token": input,
                    "cached_input_nanodollars_per_token": 0,
                    "cache_write_nanodollars_per_token": 0,
                    "output_nanodollars_per_token": input
                }]
            }]
        },
        "providers": {"provider:openai": "openai"}
    })
}

fn good_card(label: &str, input: u64) -> String {
    card(label, input, "2026-01-01T00:00:00Z").to_string()
}

fn usage_config(pricing_json: Option<&str>) -> prost_reflect::DynamicMessage {
    let desc = proxy_api::descriptor_pool()
        .get_message_by_name("llmproxy.filters.v0.Usage")
        .expect("Usage is compiled into proxy-api");
    let mut message = prost_reflect::DynamicMessage::new(desc);
    message.set_field_by_name("dialect", prost_reflect::Value::String("openai".into()));
    if let Some(json) = pricing_json {
        message.set_field_by_name("pricing_json", prost_reflect::Value::String(json.into()));
    }
    message
}

/// Builds the chain's usage filter the way a worker does, so its registry is
/// registered under the chain's scope and name.
fn install_usage_filter(
    factory_state: &Arc<SharedFactoryState>,
    stat_prefix: &str,
    pricing_json: Option<&str>,
) {
    let ctx = FactoryContext {
        shared: Arc::clone(factory_state),
        scope: format!("{SCOPE} {stat_prefix}"),
        stat_prefix: stat_prefix.to_string(),
    };
    UsageFilterFactory
        .create(&usage_config(pricing_json), &ctx)
        .expect("the usage filter builds");
}

/// A chain with no `llmproxy.auth`: no store.
fn chain_without_store(pricing_json: Option<&str>) -> Arc<SharedFactoryState> {
    let factory_state = Arc::new(SharedFactoryState::default());
    install_usage_filter(&factory_state, CHAIN, pricing_json);
    factory_state
}

fn temp_redb(hint: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "llm-proxy-admin-pricing-{hint}-{}-{}.redb",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

/// A chain with `llmproxy.auth` over a durable redb store. The control plane is
/// registered first, as the filter order does.
fn chain_with_durable_store(
    path: &std::path::Path,
    pricing_json: Option<&str>,
) -> (Arc<SharedFactoryState>, Arc<ControlPlane>) {
    let factory_state = Arc::new(SharedFactoryState::default());
    let control_plane = Arc::new(
        ControlPlane::new(
            Box::new(RedbControlPlaneStore::open(path).expect("redb opens")),
            HmacSecret::new(TEST_HMAC_SECRET),
            KeySet::new(),
        )
        .expect("an empty store boots"),
    );
    let registered = Arc::clone(&control_plane);
    factory_state
        .get_or_try_init(
            &format!("{SCOPE} {CHAIN}"),
            CHAIN,
            auth_filter::TYPE_URL,
            move || Ok(registered as Arc<dyn std::any::Any + Send + Sync>),
        )
        .expect("registering the control plane");
    install_usage_filter(&factory_state, CHAIN, pricing_json);
    (factory_state, control_plane)
}

async fn started(factory_state: Arc<SharedFactoryState>, token: Option<&str>) -> SocketAddr {
    let (server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        token.map(str::to_string),
    )
    .await;
    // The server task outlives this handle (dropping it does not stop it), and
    // every test binds its own ephemeral port.
    std::mem::forget(server);
    addr
}

async fn put(addr: SocketAddr, token: Option<&str>, body: &str) -> (StatusCode, serde_json::Value) {
    let (status, _headers, text) = request(addr, "PUT", "/pricing", token, body).await;
    let json = serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text));
    (status, json)
}

async fn active_version(addr: SocketAddr) -> String {
    let (status, body) = get(addr, "/pricing").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    serde_json::from_str::<serde_json::Value>(&body).unwrap()["rate_card_version"]
        .as_str()
        .unwrap()
        .to_string()
}

// --- the gates --------------------------------------------------------------

#[tokio::test]
async fn put_pricing_is_refused_when_no_admin_token_is_configured() {
    let addr = started(chain_without_store(None), None).await;
    let (status, _) = put(addr, Some(ADMIN_TOKEN), &good_card("v1", 10)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unset never means open");
}

#[tokio::test]
async fn put_pricing_needs_the_right_bearer_token() {
    let addr = started(chain_without_store(None), Some(ADMIN_TOKEN)).await;
    let (status, _) = put(addr, None, &good_card("v1", 10)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no token");
    let (status, _) = put(addr, Some("not-the-token"), &good_card("v1", 10)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "wrong token");
    let (status, _) = get(addr, "/pricing").await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "neither attempt installed a card"
    );
}

// --- no store ---------------------------------------------------------------

/// The old behaviour was a 503 without `llmproxy.auth`, though the write only
/// needs the registry. It now works and says it is not persisted.
#[tokio::test]
async fn put_pricing_works_without_a_store_and_says_it_was_not_persisted() {
    let addr = started(chain_without_store(None), Some(ADMIN_TOKEN)).await;
    let (status, body) = put(addr, Some(ADMIN_TOKEN), &good_card("v1", 10)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["persisted"], false);
    assert!(
        body["note"].as_str().unwrap().contains("this process only"),
        "{body}"
    );
    assert_eq!(body["rate_card_version"], active_version(addr).await);
}

#[tokio::test]
async fn the_scoped_route_reaches_its_own_chain_and_an_unknown_chain_is_unavailable() {
    let factory_state = chain_without_store(None);
    install_usage_filter(&factory_state, "other-chain", None);
    let addr = started(factory_state, Some(ADMIN_TOKEN)).await;

    let (status, _, body) = request(
        addr,
        "PUT",
        "/chains/other-chain/pricing",
        Some(ADMIN_TOKEN),
        &good_card("scoped", 10),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = get(addr, "/chains/other-chain/pricing").await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = get(addr, "/chains/priced-chain/pricing").await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "the other chain was not touched"
    );

    let (status, _, _) = request(
        addr,
        "PUT",
        "/chains/no-such-chain/pricing",
        Some(ADMIN_TOKEN),
        &good_card("x", 10),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

// --- with a store -----------------------------------------------------------

#[tokio::test]
async fn put_pricing_with_a_durable_store_writes_the_store_and_says_so() {
    let path = temp_redb("durable");
    let (factory_state, control_plane) = chain_with_durable_store(&path, None);
    let addr = started(factory_state, Some(ADMIN_TOKEN)).await;
    let generation_before = control_plane.store().policy_generation().unwrap();

    let (status, body) = put(addr, Some(ADMIN_TOKEN), &good_card("v1", 10)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["persisted"], true);
    // A redb file is one replica's: the note must not promise propagation.
    assert!(
        body["note"]
            .as_str()
            .unwrap()
            .contains("other replicas do not read it"),
        "{body}"
    );

    let stored = control_plane.store().load().unwrap().rate_cards;
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].chain, CHAIN);
    assert_eq!(stored[0].version, body["rate_card_version"]);
    assert!(
        control_plane.store().policy_generation().unwrap() > generation_before,
        "the write bumped the generation so other replicas notice it"
    );
    assert_eq!(body["rate_card_version"], active_version(addr).await);
    std::fs::remove_file(&path).ok();
}

#[tokio::test]
async fn a_card_published_over_http_survives_a_restart_and_beats_the_configuration() {
    let path = temp_redb("restart");
    let configured = good_card("configured", 1);
    let published_version;
    {
        let (factory_state, control_plane) = chain_with_durable_store(&path, Some(&configured));
        let (server, addr) = start_full(
            snapshot_with_secret(),
            None,
            Arc::clone(&factory_state),
            Some(ADMIN_TOKEN.to_string()),
        )
        .await;
        let (_, body) = put(addr, Some(ADMIN_TOKEN), &good_card("published", 2)).await;
        published_version = body["rate_card_version"].as_str().unwrap().to_string();
        // "Stop the process": nothing may keep the redb file open.
        server.abort();
        drop((factory_state, control_plane, server));
    }
    // The file lock is released when the last handle drops, which the aborted
    // server task does a moment after `abort`.
    let deadline = Instant::now() + Duration::from_secs(5);
    while RedbControlPlaneStore::open(&path).is_err() {
        assert!(
            Instant::now() < deadline,
            "the old process never let go of the file"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // A new process, started with the same (older) configuration.
    let (factory_state, _cp) = chain_with_durable_store(&path, Some(&configured));
    let addr = started(factory_state, Some(ADMIN_TOKEN)).await;
    assert_eq!(active_version(addr).await, published_version);
    std::fs::remove_file(&path).ok();
}

#[tokio::test]
async fn an_in_memory_store_is_not_reported_as_persisted() {
    let factory_state = Arc::new(SharedFactoryState::default());
    register_control_plane(
        &factory_state,
        &format!("{SCOPE} {CHAIN}"),
        CHAIN,
        TEST_HMAC_SECRET,
    );
    install_usage_filter(&factory_state, CHAIN, None);
    let addr = started(factory_state, Some(ADMIN_TOKEN)).await;
    let (status, body) = put(addr, Some(ADMIN_TOKEN), &good_card("v1", 10)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["persisted"], false, "it dies with the process");
}

// --- validation -------------------------------------------------------------

#[tokio::test]
async fn put_pricing_rejects_invalid_json_and_a_future_effective_from() {
    let addr = started(
        chain_without_store(Some(&good_card("kept", 10))),
        Some(ADMIN_TOKEN),
    )
    .await;
    let kept = active_version(addr).await;

    let (status, _) = put(addr, Some(ADMIN_TOKEN), "{ this is not json").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, body) = put(
        addr,
        Some(ADMIN_TOKEN),
        &card("future", 10, "2999-01-01T00:00:00Z").to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.as_str().unwrap().contains("effective_from"), "{body}");

    assert_eq!(active_version(addr).await, kept, "neither changed the card");
}

// --- body cap ---------------------------------------------------------------

/// A valid card padded with catalog text to `bytes` bytes in total.
fn card_of_size(bytes: usize) -> String {
    let mut document = card("sized", 10, "2026-01-01T00:00:00Z");
    document["catalog"] = serde_json::json!({ "padding": "" });
    let empty = document.to_string().len();
    document["catalog"]["padding"] = "x".repeat(bytes - empty).into();
    let out = document.to_string();
    assert_eq!(out.len(), bytes);
    out
}

#[tokio::test]
async fn the_pricing_body_cap_is_far_above_the_generic_cap_and_still_finite() {
    let addr = started(chain_without_store(None), Some(ADMIN_TOKEN)).await;

    // Just under the cap: accepted.
    let just_under = card_of_size(MAX_PRICING_BODY_BYTES - 16);
    let (status, body) = put(addr, Some(ADMIN_TOKEN), &just_under).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Over it: refused before the card is looked at.
    let over = "x".repeat(MAX_PRICING_BODY_BYTES + 1);
    let (status, _) = put(addr, Some(ADMIN_TOKEN), &over).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

/// The shipped OpenRouter card, sent the way the admin UI sends it: it was
/// refused with a 413 under the generic cap.
#[tokio::test]
async fn the_shipped_openrouter_card_with_its_catalog_is_accepted() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/llmproxy-openrouter.yaml"
    );
    // The example is JSON, which is a YAML subset.
    let config: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("the example ships"))
            .expect("the example is JSON");
    let body = serde_json::json!({
        "price_list": config["pricing"]["price_list"],
        "providers": {"provider:openrouter": "openrouter"},
        "catalog": config["pricing"]["catalog"],
    })
    .to_string();
    assert!(
        body.len() > MAX_ADMIN_BODY_BYTES * 4,
        "the fixture must be the large card this cap exists for: {} bytes",
        body.len()
    );

    let addr = started(chain_without_store(None), Some(ADMIN_TOKEN)).await;
    let (status, response) = put(addr, Some(ADMIN_TOKEN), &body).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["rate_card_version"], active_version(addr).await);
}

#[tokio::test]
async fn every_other_write_keeps_the_generic_cap() {
    let (factory_state, _) = factory_state_with_control_plane();
    install_usage_filter(&factory_state, TEST_CHAIN_STAT_PREFIX, None);
    let addr = started(factory_state, Some(ADMIN_TOKEN)).await;
    let big = format!(r#"{{"tenant":"{}"}}"#, "t".repeat(MAX_ADMIN_BODY_BYTES));
    let (status, _, _) = request(addr, "POST", "/tenants", Some(ADMIN_TOKEN), &big).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}
