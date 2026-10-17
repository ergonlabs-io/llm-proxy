//! Where the rate card comes from and how it moves between replicas: boot
//! precedence between the configuration and the store, `PUT /pricing`, the
//! policy poll, reload, and the date check. These drive the real registry and
//! real `ControlPlane`s over one shared store; only the store behind them is
//! an in-memory stand-in for Redis.

use super::*;

use crate::auth::{HmacSecret, KeySet};
use crate::control::log_capture::Capture;
use crate::control::{ControlPlaneStore, SharedMemoryStore};

const CHAIN: &str = "chain";

/// A wire document with one priced model. `input` is the per-token price, so
/// two cards with different `input` differ in price; `clusters` is the
/// cluster-to-provider map.
fn card_json_dated(label: &str, input: u64, clusters: &[(&str, &str)], effective: &str) -> String {
    let providers: serde_json::Map<String, serde_json::Value> = clusters
        .iter()
        .map(|(cluster, provider)| (cluster.to_string(), (*provider).into()))
        .collect();
    serde_json::json!({
        "price_list": {
            "version": label,
            "effective_from": effective,
            "entries": [{
                "provider_type": "openai",
                "model": "gpt-5",
                "tier_mode": "whole_request",
                "tiers": [{
                    "up_to": null,
                    "input_nanodollars_per_token": input,
                    "cached_input_nanodollars_per_token": 0,
                    "cache_write_nanodollars_per_token": 0,
                    "output_nanodollars_per_token": input
                }]
            }]
        },
        "providers": providers,
    })
    .to_string()
}

fn card_json(label: &str, input: u64) -> String {
    card_json_dated(
        label,
        input,
        &[("provider:openai", "openai")],
        "2026-01-01T00:00:00Z",
    )
}

fn context(json: &str) -> PricingContext {
    parse_card_json(json).expect("the test card is valid")
}

fn version_of(json: &str) -> String {
    context(json).list.version().to_string()
}

fn registry() -> Arc<PricingRegistry> {
    Arc::new(PricingRegistry::new(CHAIN))
}

fn active(registry: &PricingRegistry) -> Option<String> {
    registry
        .snapshot()
        .map(|card| card.list.version().to_string())
}

fn control_plane(store: &SharedMemoryStore) -> Arc<ControlPlane> {
    Arc::new(
        ControlPlane::new(
            Box::new(store.handle()),
            HmacSecret::new(b"rate-card-test-secret"),
            KeySet::new(),
        )
        .expect("an in-memory store boots"),
    )
}

fn apply(
    registry: &Arc<PricingRegistry>,
    json: Option<&str>,
    store: Option<&Arc<ControlPlane>>,
) -> Result<(), ConfigError> {
    registry.apply_config(
        json.map(context),
        store.cloned(),
        "typed_config.pricing_json",
    )
}

// --- propagation ----------------------------------------------------------

/// The acceptance case: a card published on one replica is priced with on the
/// other after that replica's poll, and not before.
#[test]
fn a_card_published_on_one_replica_reaches_the_other_after_its_poll() {
    let (store, _) = SharedMemoryStore::new();
    let (cp_a, cp_b) = (control_plane(&store), control_plane(&store));
    let (a, b) = (registry(), registry());
    apply(&a, None, Some(&cp_a)).unwrap();
    apply(&b, None, Some(&cp_b)).unwrap();

    let v1 = a.publish_json(&card_json("v1", 10)).unwrap();
    assert!(v1.persisted, "a durable store persists the card");
    assert_eq!(
        active(&a),
        Some(v1.rate_card_version.clone()),
        "at once locally"
    );
    assert_eq!(
        active(&b),
        None,
        "before its poll the other replica still has the old (empty) card"
    );

    assert_eq!(
        cp_b.poll_once(),
        Ok(true),
        "the bumped generation triggers a reload"
    );
    assert_eq!(active(&b), Some(v1.rate_card_version.clone()));
    assert_eq!(
        serde_json::to_value(a.json_view().unwrap()).unwrap(),
        serde_json::to_value(b.json_view().unwrap()).unwrap(),
        "both replicas serve the same card, byte for byte"
    );

    // And back the other way, replacing a card both already hold.
    let v2 = b.publish_json(&card_json("v2", 20)).unwrap();
    assert_eq!(active(&a), Some(v1.rate_card_version));
    assert_eq!(cp_a.poll_once(), Ok(true));
    assert_eq!(active(&a), Some(v2.rate_card_version));
}

#[test]
fn a_card_for_one_chain_leaves_another_chain_unchanged_on_both_replicas() {
    let (store, _) = SharedMemoryStore::new();
    let (cp_a, cp_b) = (control_plane(&store), control_plane(&store));
    let chain_x = |cp: &Arc<ControlPlane>| {
        let registry = Arc::new(PricingRegistry::new("chain-x"));
        apply(&registry, Some(&card_json("x", 1)), Some(cp)).unwrap();
        registry
    };
    let (main_a, main_b) = (registry(), registry());
    apply(&main_a, Some(&card_json("main", 5)), Some(&cp_a)).unwrap();
    apply(&main_b, Some(&card_json("main", 5)), Some(&cp_b)).unwrap();
    let (x_a, x_b) = (chain_x(&cp_a), chain_x(&cp_b));
    let x_before = active(&x_a);

    main_a.publish_json(&card_json("main-2", 50)).unwrap();
    cp_a.poll_once().unwrap();
    cp_b.poll_once().unwrap();

    assert_eq!(
        active(&main_b),
        active(&main_a),
        "the published chain converges"
    );
    assert_eq!(active(&x_a), x_before, "the other chain is untouched here");
    assert_eq!(active(&x_b), x_before, "and on the other replica");
}

/// An unrelated generation bump must not hand a replica a card it has.
#[test]
fn an_unrelated_write_does_not_reinstall_the_card() {
    let (store, _) = SharedMemoryStore::new();
    let (cp_a, cp_b) = (control_plane(&store), control_plane(&store));
    let b = registry();
    apply(&b, None, Some(&cp_b)).unwrap();
    cp_a.put_rate_card(&StoredRateCard {
        chain: CHAIN.into(),
        version: "v".into(),
        card_json: context(&card_json("v1", 10)).to_wire_json(),
    })
    .unwrap();
    cp_b.poll_once().unwrap();

    let (capture, guard) = Capture::start();
    cp_a.create_tenant(&crate::auth::TenantId::new("t"))
        .unwrap();
    cp_b.poll_once().unwrap();
    drop(guard);
    assert!(
        capture
            .rendered_at_or_above(tracing::Level::INFO)
            .iter()
            .all(|line| !line.contains("installed the rate card")),
        "the card did not change, so nothing is installed or logged"
    );
}

// --- boot precedence --------------------------------------------------------

#[test]
fn an_empty_store_is_seeded_from_the_configured_card() {
    let (store, _) = SharedMemoryStore::new();
    let cp = control_plane(&store);
    let r = registry();
    let configured = card_json("configured", 10);
    apply(&r, Some(&configured), Some(&cp)).unwrap();

    assert_eq!(active(&r), Some(version_of(&configured)));
    let stored = cp
        .rate_card(CHAIN)
        .expect("the configured card seeded the store");
    assert_eq!(stored.version, version_of(&configured));
    assert_eq!(
        store.inner.load().unwrap().rate_cards,
        vec![stored],
        "and it is in the store itself, not only this control plane's view"
    );
}

#[test]
fn a_stored_card_wins_over_a_different_configured_card_and_is_logged_once() {
    let (store, _) = SharedMemoryStore::new();
    let published = card_json("published", 99);
    {
        let cp = control_plane(&store);
        let r = registry();
        apply(&r, None, Some(&cp)).unwrap();
        r.publish_json(&published).unwrap();
    }

    let cp = control_plane(&store);
    let r = registry();
    let (capture, guard) = Capture::start();
    // Three workers build the same chain with the same configuration.
    for _ in 0..3 {
        apply(&r, Some(&card_json("configured", 10)), Some(&cp)).unwrap();
    }
    drop(guard);

    assert_eq!(active(&r), Some(version_of(&published)), "the store wins");
    assert_eq!(
        cp.rate_card(CHAIN).unwrap().version,
        version_of(&published),
        "and the store is left as it was"
    );
    let lines: Vec<_> = capture
        .rendered_at_or_above(tracing::Level::INFO)
        .into_iter()
        .filter(|line| line.contains("stored card stays in force"))
        .collect();
    assert_eq!(
        lines.len(),
        1,
        "logged once, not once per worker: {lines:?}"
    );
}

#[test]
fn a_restart_keeps_the_published_card() {
    let (store, _) = SharedMemoryStore::new();
    let configured = card_json("configured", 10);
    let published = card_json("published", 77);
    {
        let cp = control_plane(&store);
        let r = registry();
        apply(&r, Some(&configured), Some(&cp)).unwrap();
        r.publish_json(&published).unwrap();
    }
    // A new process: new control plane, new registry, the same configuration.
    let cp = control_plane(&store);
    let r = registry();
    apply(&r, Some(&configured), Some(&cp)).unwrap();
    assert_eq!(active(&r), Some(version_of(&published)));
}

#[test]
fn a_replica_that_seeds_second_adopts_the_card_that_won() {
    let (store, _) = SharedMemoryStore::new();
    let (cp_a, cp_b) = (control_plane(&store), control_plane(&store));
    let (a, b) = (registry(), registry());
    // `cp_b` loaded before `a` seeded, so its view of the store is empty.
    apply(&a, Some(&card_json("first", 1)), Some(&cp_a)).unwrap();
    apply(&b, Some(&card_json("second", 2)), Some(&cp_b)).unwrap();
    assert_eq!(active(&b), active(&a), "the first seed stands");
    assert_eq!(active(&b), Some(version_of(&card_json("first", 1))));
}

/// The legacy-order case: the usage filter built before `llmproxy.auth`.
#[test]
fn a_store_attached_after_the_usage_filter_is_built_still_takes_over() {
    let (store, _) = SharedMemoryStore::new();
    let cp = control_plane(&store);
    let r = registry();
    apply(&r, Some(&card_json("configured", 10)), None).unwrap();
    assert!(!r.publish_json(&card_json("local", 11)).unwrap().persisted);

    r.attach_control_plane(&cp, "typed_config").unwrap();
    assert!(
        cp.rate_card(CHAIN).is_some(),
        "the card is now in the store"
    );
    let published = r.publish_json(&card_json("after", 12)).unwrap();
    assert!(published.persisted);
    assert_eq!(
        cp.rate_card(CHAIN).unwrap().version,
        published.rate_card_version
    );
}

// --- reload and PUT without a store ----------------------------------------

#[test]
fn without_a_store_a_changed_configured_card_is_installed_on_reload() {
    let r = registry();
    let first = card_json("first", 10);
    apply(&r, Some(&first), None).unwrap();
    assert_eq!(active(&r), Some(version_of(&first)));

    let second = card_json("second", 20);
    apply(&r, Some(&second), None).unwrap();
    assert_eq!(
        active(&r),
        Some(version_of(&second)),
        "the reload replaced the card"
    );
}

#[test]
fn without_a_store_a_reload_that_did_not_change_the_card_keeps_a_put_card() {
    let r = registry();
    let configured = card_json("configured", 10);
    apply(&r, Some(&configured), None).unwrap();
    let put = r.publish_json(&card_json("put", 30)).unwrap();
    assert!(!put.persisted, "no store: not persisted");

    // Every worker builds the chain again with the unchanged configuration.
    apply(&r, Some(&configured), None).unwrap();
    assert_eq!(active(&r), Some(put.rate_card_version.clone()));

    // A changed configuration is the operator's newer decision.
    let changed = card_json("changed", 40);
    apply(&r, Some(&changed), None).unwrap();
    assert_eq!(active(&r), Some(version_of(&changed)));

    // Removing pricing from the configuration clears the card, loudly.
    let (capture, guard) = Capture::start();
    apply(&r, None, None).unwrap();
    drop(guard);
    assert_eq!(active(&r), None);
    assert_eq!(
        capture.rendered_at_or_above(tracing::Level::WARN).len(),
        1,
        "clearing the card is a warning"
    );
}

#[test]
fn with_a_store_a_reload_never_replaces_the_stored_card() {
    let (store, _) = SharedMemoryStore::new();
    let cp = control_plane(&store);
    let r = registry();
    apply(&r, Some(&card_json("first", 10)), Some(&cp)).unwrap();
    let published = r.publish_json(&card_json("published", 50)).unwrap();

    let changed = card_json("changed", 60);
    apply(&r, Some(&changed), Some(&cp)).unwrap();
    assert_eq!(active(&r), Some(published.rate_card_version.clone()));
    assert_eq!(
        cp.rate_card(CHAIN).unwrap().version,
        published.rate_card_version
    );

    // Removing pricing from the configuration does not clear a stored card.
    apply(&r, None, Some(&cp)).unwrap();
    assert_eq!(active(&r), Some(published.rate_card_version));
}

/// `PUT /pricing` says where the card lives per store kind. Only a shared
/// store reaches other replicas; `persistent` is one replica's file, so its
/// note must not promise propagation.
#[test]
fn the_publish_note_says_which_stores_survive_a_restart_and_reach_other_replicas() {
    let path = std::env::temp_dir().join(format!(
        "llm-proxy-rate-card-note-{}-{}.redb",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let (shared, _) = SharedMemoryStore::new();
    let cases: [(&str, Box<dyn ControlPlaneStore>, bool, &str); 3] = [
        (
            "in_memory",
            Box::new(crate::control::InMemoryControlPlaneStore::default()),
            false,
            "a restart loses it",
        ),
        (
            "persistent",
            Box::new(crate::control::RedbControlPlaneStore::open(&path).unwrap()),
            true,
            "other replicas do not read it",
        ),
        (
            "shared",
            Box::new(shared.handle()),
            true,
            "replicas that share it install it",
        ),
    ];
    for (kind, store, persisted, note) in cases {
        let cp = Arc::new(ControlPlane::new(store, HmacSecret::new(b"s"), KeySet::new()).unwrap());
        let r = registry();
        apply(&r, None, Some(&cp)).unwrap();
        let published = r.publish_json(&card_json("v1", 10)).unwrap();
        assert_eq!(published.persisted, persisted, "{kind}");
        assert!(published.note.contains(note), "{kind}: {}", published.note);
        assert!(
            cp.rate_card(CHAIN).is_some(),
            "{kind}: the card is in the store"
        );
    }
    let _ = std::fs::remove_file(&path);
}

// --- refusals ---------------------------------------------------------------

#[test]
fn a_refused_store_write_changes_nothing() {
    let (store, _) = SharedMemoryStore::new();
    let cp = control_plane(&store);
    let r = registry();
    apply(&r, Some(&card_json("first", 10)), Some(&cp)).unwrap();
    let before = active(&r);

    store
        .refuse_rate_cards
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let error = r.publish_json(&card_json("second", 20)).unwrap_err();
    assert!(matches!(error, PublishError::Store(_)), "{error:?}");
    assert_eq!(
        active(&r),
        before,
        "this replica did not move ahead of the store"
    );
}

#[test]
fn a_future_dated_card_is_refused_on_put_at_boot_and_from_the_store() {
    let future = "2999-01-01T00:00:00Z";
    let future_card = card_json_dated("future", 10, &[("provider:openai", "openai")], future);

    // PUT
    let r = registry();
    let error = r.publish_json(&future_card).unwrap_err();
    let PublishError::Invalid(message) = error else {
        panic!("expected Invalid");
    };
    assert!(
        message.contains("effective_from") && message.contains("future"),
        "{message}"
    );
    assert_eq!(active(&r), None);

    // Boot (and reload): a load error at the configuration field.
    let error = apply(&registry(), Some(&future_card), None).unwrap_err();
    let ConfigError::InvalidValue { field_path, reason } = error else {
        panic!("expected InvalidValue");
    };
    assert_eq!(field_path, "typed_config.pricing_json");
    assert!(reason.contains("effective_from"), "{reason}");

    // From the store: not installed, and the previous card stays.
    let (store, raw) = SharedMemoryStore::new();
    let cp = control_plane(&store);
    let r = registry();
    apply(&r, Some(&card_json("current", 10)), Some(&cp)).unwrap();
    let before = active(&r);
    let (capture, guard) = Capture::start();
    raw.put_rate_card(&StoredRateCard {
        chain: CHAIN.into(),
        version: "future".into(),
        card_json: context(&future_card).to_wire_json(),
    })
    .unwrap();
    cp.poll_once().unwrap();
    drop(guard);
    assert_eq!(active(&r), before);
    assert_eq!(capture.rendered_at_or_above(tracing::Level::WARN).len(), 1);
}

/// A card the writer dated "now" can look a little ahead to a replica whose
/// clock is behind. That must not strand the replica on the old card.
#[test]
fn a_stored_card_a_little_ahead_of_this_clock_is_still_installed() {
    let soon = (chrono::Utc::now() + chrono::Duration::seconds(60)).to_rfc3339();
    let json = card_json_dated("soon", 10, &[("provider:openai", "openai")], &soon);
    let (store, raw) = SharedMemoryStore::new();
    let cp = control_plane(&store);
    let r = registry();
    apply(&r, None, Some(&cp)).unwrap();
    raw.put_rate_card(&StoredRateCard {
        chain: CHAIN.into(),
        version: "soon".into(),
        card_json: context(&json).to_wire_json(),
    })
    .unwrap();
    cp.poll_once().unwrap();
    assert_eq!(active(&r), Some(version_of(&json)));

    // The same date is refused where this process is the authority.
    assert!(registry().publish_json(&json).is_err());
}

#[test]
fn an_unusable_stored_card_keeps_the_previous_card_and_warns() {
    let (store, raw) = SharedMemoryStore::new();
    let cp = control_plane(&store);
    let r = registry();
    apply(&r, Some(&card_json("current", 10)), Some(&cp)).unwrap();
    let before = active(&r);

    let (capture, guard) = Capture::start();
    raw.put_rate_card(&StoredRateCard {
        chain: CHAIN.into(),
        version: "bad".into(),
        card_json: "{not a card".into(),
    })
    .unwrap();
    cp.poll_once().unwrap();
    drop(guard);

    assert_eq!(active(&r), before);
    let warnings = capture.rendered_at_or_above(tracing::Level::WARN);
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains(CHAIN));
}

#[test]
fn a_garbage_put_is_a_400_class_error_and_changes_nothing() {
    let r = registry();
    apply(&r, Some(&card_json("current", 10)), None).unwrap();
    let before = active(&r);
    assert!(matches!(
        r.publish_json("not json"),
        Err(PublishError::Invalid(_))
    ));
    assert_eq!(active(&r), before);
}

// --- version and legacy carrier --------------------------------------------

#[test]
fn the_published_version_changes_when_only_the_provider_map_changes() {
    let r = registry();
    let one = r
        .publish_json(&card_json_dated(
            "v",
            10,
            &[("provider:a", "openai")],
            "2026-01-01T00:00:00Z",
        ))
        .unwrap();
    let two = r
        .publish_json(&card_json_dated(
            "v",
            10,
            &[("provider:b", "openai")],
            "2026-01-01T00:00:00Z",
        ))
        .unwrap();
    assert_ne!(one.rate_card_version, two.rate_card_version);
}

#[test]
fn the_legacy_carrier_registers_its_registry_so_pricing_can_reach_it() {
    let ctx = FactoryContext {
        shared: Arc::new(proxy_http::filter::SharedFactoryState::default()),
        scope: "scope".into(),
        stat_prefix: "legacy-chain".into(),
    };
    let desc = proxy_api::descriptor_pool()
        .get_message_by_name("envoy.config.core.v3.DataSource")
        .unwrap();
    let mut config = DynamicMessage::new(desc);
    let wire = serde_json::json!({
        "dialect": "openai",
        "price_list": serde_json::from_str::<serde_json::Value>(&card_json("legacy", 10)).unwrap()["price_list"],
        "providers": {"provider:openai": "openai"},
    });
    config.set_field_by_name(
        "inline_string",
        prost_reflect::Value::String(wire.to_string()),
    );
    LegacyUsageFilterFactory.create(&config, &ctx).unwrap();

    let registry = ctx
        .shared
        .get_by_name("legacy-chain", TYPE_URL)
        .expect("the legacy carrier registers its registry by chain name")
        .downcast::<PricingRegistry>()
        .unwrap();
    assert_eq!(
        active(&registry),
        Some(version_of(&card_json("legacy", 10)))
    );
    assert!(registry.publish_json(&card_json("put", 11)).is_ok());
}

/// Dollar enforcement and the recorded list cost both come from the one
/// pricing function, so a graduated card with cache tokens agrees in both.
#[test]
fn dollar_enforcement_agrees_with_graduated_pricing_of_cache_tokens() {
    let tier = |up_to: serde_json::Value, i: u64, c: u64, w: u64, o: u64| {
        serde_json::json!({"up_to": up_to, "input_nanodollars_per_token": i,
            "cached_input_nanodollars_per_token": c, "cache_write_nanodollars_per_token": w,
            "output_nanodollars_per_token": o})
    };
    let card = serde_json::json!({
        "price_list": {"effective_from": "2026-01-01T00:00:00Z", "entries": [{
            "provider_type": "openai", "model": "gpt-5", "tier_mode": "graduated",
            "tiers": [tier(1000.into(), 1000, 100, 1200, 5000),
                      tier(serde_json::Value::Null, 2000, 200, 2400, 10000)]}]},
        "providers": {"provider:openai": "openai"}
    })
    .to_string();
    let r = registry();
    r.publish_json(&card).unwrap();
    let usage = TokenUsage {
        input_tokens: 500,
        cached_tokens: 800,
        cache_creation_tokens: 0,
        output_tokens: 10,
    };
    // 980,000 nanodollars, rounded up to micro-dollars.
    assert_eq!(
        r.cost_micro_usd(Some("provider:openai"), Some("gpt-5"), &usage),
        Some(980)
    );
}

// --- concurrent publish ----------------------------------------------------

/// Delegates to a shared store, but right after the first rate card write it
/// performs another replica's write of `rival`, which is the interleaving
/// `ControlPlane::put_rate_card` cannot rule out: B writes after A's put and
/// before A's read-back.
struct RivalWritesAfterFirstPut {
    inner: SharedMemoryStore,
    rival: StoredRateCard,
    pending: std::sync::atomic::AtomicBool,
}

// Rust note: the trait has no default for most methods, so a wrapper must
// forward every one; only `put_rate_card` adds behaviour.
impl ControlPlaneStore for RivalWritesAfterFirstPut {
    fn add_window_batch(
        &self,
        scope: &str,
        node_id: &str,
        rows: &[crate::control::WindowDelta<'_>],
    ) -> Vec<Result<u64, crate::control::StoreError>> {
        self.inner.add_window_batch(scope, node_id, rows)
    }
    fn last_window_seq_batch(
        &self,
        scope: &str,
        node_id: &str,
        rows: &[crate::control::WindowRow],
    ) -> Vec<Result<u64, crate::control::StoreError>> {
        self.inner.last_window_seq_batch(scope, node_id, rows)
    }
    fn load_window_batch(
        &self,
        scope: &str,
        rows: &[crate::control::WindowRow],
    ) -> Vec<Result<u64, crate::control::StoreError>> {
        self.inner.load_window_batch(scope, rows)
    }
    fn load(&self) -> Result<crate::control::StoredControlPlane, crate::control::StoreError> {
        self.inner.load()
    }
    fn policy_generation(&self) -> Result<u64, crate::control::StoreError> {
        self.inner.policy_generation()
    }
    fn create_tenant(&self, t: &crate::auth::TenantId) -> Result<(), crate::control::StoreError> {
        self.inner.create_tenant(t)
    }
    fn delete_tenant(&self, t: &crate::auth::TenantId) -> Result<(), crate::control::StoreError> {
        self.inner.delete_tenant(t)
    }
    fn put_key(&self, rec: &crate::control::StoredKey) -> Result<(), crate::control::StoreError> {
        self.inner.put_key(rec)
    }
    fn revoke_key(&self, k: &crate::auth::KeyId) -> Result<(), crate::control::StoreError> {
        self.inner.revoke_key(k)
    }
    fn set_policy(
        &self,
        t: &crate::auth::TenantId,
        a: &crate::model_authz::ModelAccess,
    ) -> Result<(), crate::control::StoreError> {
        self.inner.set_policy(t, a)
    }
    fn set_budget(
        &self,
        t: &crate::auth::TenantId,
        b: Option<&crate::spend::TenantBudget>,
    ) -> Result<(), crate::control::StoreError> {
        self.inner.set_budget(t, b)
    }
    fn set_limits(
        &self,
        subject: &crate::auth::TenantId,
        limits: Option<&crate::control::LimitPolicy>,
    ) -> Result<(), crate::control::StoreError> {
        self.inner.set_limits(subject, limits)
    }
    fn put_rate_card(&self, card: &StoredRateCard) -> Result<(), crate::control::StoreError> {
        self.inner.put_rate_card(card)?;
        if self
            .pending
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            self.inner.put_rate_card(&self.rival)?;
        }
        Ok(())
    }
    fn put_rate_card_if_absent(
        &self,
        card: &StoredRateCard,
    ) -> Result<bool, crate::control::StoreError> {
        self.inner.put_rate_card_if_absent(card)
    }
    fn is_durable(&self) -> bool {
        true
    }
    fn add_spend(
        &self,
        s: &str,
        t: &crate::auth::TenantId,
        p: &crate::spend::PeriodKey,
        d: u64,
        token: crate::control::FlushToken<'_>,
    ) -> Result<u64, crate::control::StoreError> {
        self.inner.add_spend(s, t, p, d, token)
    }
    fn overwrite_spend(
        &self,
        s: &str,
        t: &crate::auth::TenantId,
        p: &crate::spend::PeriodKey,
        total: u64,
    ) -> Result<(), crate::control::StoreError> {
        self.inner.overwrite_spend(s, t, p, total)
    }
    fn last_flush_seq(
        &self,
        s: &str,
        t: &crate::auth::TenantId,
        p: &crate::spend::PeriodKey,
        node: &str,
    ) -> Result<u64, crate::control::StoreError> {
        self.inner.last_flush_seq(s, t, p, node)
    }
    fn load_spend(
        &self,
        s: &str,
        t: &crate::auth::TenantId,
        p: &crate::spend::PeriodKey,
    ) -> Result<u64, crate::control::StoreError> {
        self.inner.load_spend(s, t, p)
    }
}

/// Replica B writes between A's put and A's read-back. The store holds B, so
/// A must serve B: installing A's own card after the put would leave it on a
/// card the store no longer has, with every later poll skipping it.
#[test]
fn a_concurrent_publish_from_another_replica_wins_on_the_publishing_replica() {
    let (store, _) = SharedMemoryStore::new();
    let card_b = context(&card_json("card-b", 20));
    let wrapper = RivalWritesAfterFirstPut {
        inner: store.handle(),
        rival: StoredRateCard {
            chain: CHAIN.into(),
            version: card_b.list.version().to_string(),
            card_json: card_b.to_wire_json(),
        },
        pending: std::sync::atomic::AtomicBool::new(true),
    };
    let cp_a = Arc::new(
        ControlPlane::new(
            Box::new(wrapper),
            HmacSecret::new(b"rate-card-test-secret"),
            KeySet::new(),
        )
        .expect("an in-memory store boots"),
    );
    let cp_b = control_plane(&store);
    let (a, b) = (registry(), registry());
    apply(&a, None, Some(&cp_a)).unwrap();
    apply(&b, None, Some(&cp_b)).unwrap();

    let published = a.publish_json(&card_json("card-a", 10)).unwrap();

    let want_b = card_b.list.version().to_string();
    assert_eq!(
        published.rate_card_version,
        version_of(&card_json("card-a", 10))
    );
    assert!(
        published.note.contains("superseded"),
        "the response says the write did not stay: {}",
        published.note
    );
    assert_eq!(active(&a), Some(want_b.clone()), "the store's card wins");
    assert_ne!(active(&a), Some(published.rate_card_version));

    cp_a.poll_once().unwrap();
    cp_b.poll_once().unwrap();
    assert_eq!(active(&a), Some(want_b.clone()));
    assert_eq!(active(&b), Some(want_b));
}

// --- the exported active version --------------------------------------------

/// The `llmproxy_usage_rate_card_active` series of `chain`, as
/// `(version, value)` pairs read from the rendered Prometheus text that
/// `/stats/prometheus` serves.
fn exported_cards(registry: &Registry, chain: &str) -> Vec<(String, u64)> {
    let rendered = proxy_observability::stats::prometheus_render::render(registry);
    let scope = format!(r#"scope="{chain}""#);
    let mut cards: Vec<(String, u64)> = rendered
        .lines()
        .filter(|l| l.starts_with("envoy_llmproxy_usage_rate_card_active{") && l.contains(&scope))
        .map(|line| {
            let version = line
                .split(r#"version=""#)
                .nth(1)
                .and_then(|rest| rest.split('"').next())
                .expect("a version label")
                .to_string();
            let value = line.rsplit(' ').next().unwrap().parse().unwrap();
            (version, value)
        })
        .collect();
    cards.sort();
    cards
}

/// Operators compare this series across replicas to see a card that has not
/// propagated, so the 1 must follow the card however it was installed: a local
/// publish, another replica's write arriving by poll, or the card going away.
#[test]
fn the_active_rate_card_version_is_exported_through_publish_poll_and_clear() {
    let control = proxy_observability::stats::StatsControl::new(1);
    let stats = control.registry();
    let (store, _) = SharedMemoryStore::new();
    let (cp_a, cp_b) = (control_plane(&store), control_plane(&store));
    let (a, b) = (registry(), registry());
    a.export_to(stats.clone());
    assert!(
        exported_cards(&stats, CHAIN).is_empty(),
        "no card, no series"
    );
    apply(&a, None, Some(&cp_a)).unwrap();
    apply(&b, None, Some(&cp_b)).unwrap();

    let v1 = a
        .publish_json(&card_json("v1", 10))
        .unwrap()
        .rate_card_version;
    assert_eq!(exported_cards(&stats, CHAIN), vec![(v1.clone(), 1)]);

    let v2 = a
        .publish_json(&card_json("v2", 20))
        .unwrap()
        .rate_card_version;
    let mut want = vec![(v1.clone(), 0), (v2.clone(), 1)];
    want.sort();
    assert_eq!(
        exported_cards(&stats, CHAIN),
        want,
        "the retired version drops to 0, never stays at 1"
    );

    // The other replica exports what it received from the store, on its own
    // stats registry, only after its poll.
    let other = proxy_observability::stats::StatsControl::new(1).registry();
    b.export_to(other.clone());
    assert!(exported_cards(&other, CHAIN).is_empty());
    cp_b.poll_once().unwrap();
    assert_eq!(exported_cards(&other, CHAIN), vec![(v2, 1)]);

    // Removing the configured card with no store clears the series to 0.
    let solo = registry();
    let solo_stats = proxy_observability::stats::StatsControl::new(1).registry();
    solo.export_to(solo_stats.clone());
    apply(&solo, Some(&card_json("solo", 5)), None).unwrap();
    let solo_version = version_of(&card_json("solo", 5));
    assert_eq!(
        exported_cards(&solo_stats, CHAIN),
        vec![(solo_version.clone(), 1)]
    );
    apply(&solo, None, None).unwrap();
    assert_eq!(exported_cards(&solo_stats, CHAIN), vec![(solo_version, 0)]);
}
