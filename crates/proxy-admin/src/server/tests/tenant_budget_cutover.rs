//! `PUT /tenants/{id}/budget` against the start-up cutover check.
//!
//! `llmproxy.spend_limit` refuses to start when the store holds a tenant
//! budget and `legacy_tenant_budget_cutover` is not set. A budget written at
//! runtime would therefore stop the next restart, and a rolling restart would
//! crash-loop every replica. The write is refused up front instead.

use super::*;
use proxy_filters::control::ControlPlaneSnapshot;
use proxy_filters::spend_limit_filter::SharedSpendLimitState;

const BUDGET: &str = r#"{"budget":{"max_usd":"5.00","period":"daily"}}"#;
const CLEAR: &str = r#"{"budget":null}"#;

type Handle = Arc<arc_swap::ArcSwap<ControlPlaneSnapshot>>;

/// A chain with a control plane and a spend filter whose cutover is
/// `with_cutover`, registered the way the filter factory registers it.
fn chain(with_cutover: bool) -> (Arc<SharedFactoryState>, Handle) {
    let (factory_state, handle) = factory_state_with_control_plane();
    let accumulator = Arc::new(proxy_filters::spend::SpendAccumulator::new(
        TEST_CHAIN_STAT_PREFIX.to_string(),
        Arc::new(InMemoryControlPlaneStore::default()),
        Period::Daily,
        "test-node".to_string(),
    ));
    factory_state
        .get_or_try_init(
            TEST_CHAIN_SCOPE,
            TEST_CHAIN_STAT_PREFIX,
            proxy_filters::spend_limit_filter::TYPE_URL,
            move || {
                let state = if with_cutover {
                    SharedSpendLimitState::for_test(accumulator)
                } else {
                    SharedSpendLimitState::for_test_without_cutover(accumulator)
                };
                Ok(Arc::new(state) as Arc<dyn std::any::Any + Send + Sync>)
            },
        )
        .expect("registering the spend state");
    (factory_state, handle)
}

fn has_budget(handle: &Handle) -> bool {
    handle.load().policies.values().any(|p| p.budget.is_some())
}

async fn serve_chain(factory_state: Arc<SharedFactoryState>) -> SocketAddr {
    let (server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;
    // Dropping the handle does not stop the server; each test has its own port.
    std::mem::forget(server);
    addr
}

#[tokio::test]
async fn a_tenant_budget_is_refused_naming_the_cutover_when_the_spend_filter_lacks_it() {
    let (factory_state, handle) = chain(false);
    let addr = serve_chain(factory_state).await;

    for path in [
        "/tenants/acme/budget",
        "/chains/test-chain/tenants/acme/budget",
    ] {
        let (status, _, body) = request(addr, "PUT", path, Some(ADMIN_TOKEN), BUDGET).await;
        assert_eq!(status, StatusCode::CONFLICT, "{path}: {body}");
        assert!(body.contains("legacy_tenant_budget_cutover"), "{body}");
        assert!(body.contains("START_KEYS_FRESH"), "{body}");
    }
    assert!(!has_budget(&handle), "nothing was written");
}

#[tokio::test]
async fn a_tenant_budget_is_stored_when_the_spend_filter_sets_the_cutover() {
    let (factory_state, handle) = chain(true);
    let addr = serve_chain(factory_state).await;
    let (status, ..) = request(
        addr,
        "PUT",
        "/tenants/acme/budget",
        Some(ADMIN_TOKEN),
        BUDGET,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(has_budget(&handle));
}

#[tokio::test]
async fn clearing_a_budget_and_chains_without_a_spend_filter_are_unaffected() {
    // Clearing is allowed without the cutover: it can only make a start easier.
    let (factory_state, _handle) = chain(false);
    let addr = serve_chain(factory_state).await;
    let (status, ..) = request(
        addr,
        "PUT",
        "/tenants/acme/budget",
        Some(ADMIN_TOKEN),
        CLEAR,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // No spend filter on the chain: there is no start-up check to protect.
    let (factory_state, handle) = factory_state_with_control_plane();
    let addr = serve_chain(factory_state).await;
    let (status, ..) = request(
        addr,
        "PUT",
        "/tenants/acme/budget",
        Some(ADMIN_TOKEN),
        BUDGET,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(has_budget(&handle));
}
