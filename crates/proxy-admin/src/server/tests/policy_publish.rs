//! Admin writes against a store that fails or stalls: a write whose reload
//! failed is not reported as applied, and a slow store does not stall the
//! control runtime the admin server shares with readiness and signals.

use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};

use proxy_control::control::{ControlPlaneStore, SharedMemoryStore};

/// Registers a real [`ControlPlane`] over `store` the way
/// [`register_control_plane`] does, and returns it so a test can mint keys
/// directly.
fn factory_state_with_store(
    store: SharedMemoryStore,
) -> (Arc<SharedFactoryState>, Arc<ControlPlane>) {
    let control_plane = Arc::new(
        ControlPlane::new(
            Box::new(store),
            HmacSecret::new(TEST_HMAC_SECRET),
            KeySet::new(),
        )
        .expect("an empty store must not fail ControlPlane::new"),
    );
    let factory_state = Arc::new(SharedFactoryState::default());
    let registered = Arc::clone(&control_plane);
    factory_state
        .get_or_try_init(
            TEST_CHAIN_SCOPE,
            TEST_CHAIN_STAT_PREFIX,
            auth_filter::TYPE_URL,
            || Ok(registered as Arc<dyn std::any::Any + Send + Sync>),
        )
        .expect("inserting the test ControlPlane singleton must not fail");
    (factory_state, control_plane)
}

#[tokio::test]
async fn a_revoke_whose_reload_fails_answers_503_naming_the_unapplied_write() {
    let (store, inner) = SharedMemoryStore::new();
    let hooks = Arc::clone(&store.hooks);
    let (factory_state, control_plane) = factory_state_with_store(store);
    let minted = control_plane
        .mint_key(&TenantId::new("tenant-a"), &KeyId::new("key-a"))
        .unwrap();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    // The revoke's own write lands; the reload after it fails.
    hooks.fail_loads.store(true, Ordering::SeqCst);
    let (status, _, body) = request(addr, "DELETE", "/keys/key-a", Some(ADMIN_TOKEN), "").await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(
        body.contains("written to the control-plane store, but not yet applied on this replica"),
        "the refusal must say the write is stored but not live: {body}"
    );
    assert!(
        inner
            .load()
            .unwrap()
            .keys
            .iter()
            .any(|k| k.key_id.as_str() == "key-a" && k.revoked),
        "the store must hold the revocation the body says was written"
    );
    // This replica still serves the snapshot from before the revoke, which is
    // exactly what the 503 warns about.
    assert!(matches!(
        test_authenticator(control_plane.handle())
            .authenticate(&headers_with_bearer(&minted.plaintext)),
        AuthOutcome::Authenticated(_)
    ));
}

/// A mint whose reload failed still exists in the store, and the response is
/// the only copy of its plaintext, so it is a 202 that carries the key and
/// says it is not live here yet, never an error that drops the key.
#[tokio::test]
async fn a_mint_whose_reload_fails_returns_the_key_as_202_not_applied() {
    let (store, inner) = SharedMemoryStore::new();
    let hooks = Arc::clone(&store.hooks);
    let (factory_state, control_plane) = factory_state_with_store(store);
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    hooks.fail_loads.store(true, Ordering::SeqCst);
    let (status, _, body) = request(
        addr,
        "POST",
        "/keys",
        Some(ADMIN_TOKEN),
        r#"{"tenant":"tenant-a","key_id":"key-a"}"#,
    )
    .await;

    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let minted: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(minted["applied"], serde_json::Value::Bool(false));
    let plaintext = minted["key"]
        .as_str()
        .expect("the plaintext is returned")
        .to_owned();
    assert!(inner
        .load()
        .unwrap()
        .keys
        .iter()
        .any(|k| k.key_id.as_str() == "key-a"));

    // Once a reload succeeds, the returned plaintext is the key that works.
    hooks.fail_loads.store(false, Ordering::SeqCst);
    control_plane.rebuild().unwrap();
    assert!(matches!(
        test_authenticator(control_plane.handle()).authenticate(&headers_with_bearer(&plaintext)),
        AuthOutcome::Authenticated(_)
    ));
}

/// Holds every `revoke_key` until [`Gate::open`]; opens on drop, so a failed
/// assertion does not leave store calls parked forever.
#[derive(Default)]
struct Gate {
    open: Mutex<bool>,
    changed: Condvar,
    entered: AtomicUsize,
}

impl Gate {
    fn wait(&self) {
        self.entered.fetch_add(1, Ordering::SeqCst);
        let mut open = self.open.lock().unwrap();
        while !*open {
            open = self.changed.wait(open).unwrap();
        }
    }

    fn open(&self) {
        *self.open.lock().unwrap() = true;
        self.changed.notify_all();
    }
}

struct OpenOnDrop(Arc<Gate>);

/// A runtime dropped from inside another runtime's task panics, so it is shut
/// down in the background on every exit path, including a failed assertion.
struct BackgroundRuntime(Option<tokio::runtime::Runtime>);

impl Drop for BackgroundRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
    }
}

impl Drop for OpenOnDrop {
    fn drop(&mut self) {
        self.0.open();
    }
}

/// The admin server runs on the 2-worker control runtime `main` builds, next
/// to the SIGTERM listener. Three revokes, more than the runtime has workers,
/// stall in the store; `/ready` and SIGTERM must still be answered. A handler
/// that waits on the store inline holds a worker, and the runtime stops
/// serving after the first one, so the test waits only for one to arrive. The
/// client and every bound run on this test's own runtime, so a stalled
/// control runtime cannot also stall the timeouts.
#[cfg(unix)]
#[tokio::test]
async fn a_slow_store_blocks_admin_writes_without_stalling_ready_or_sigterm() {
    use tokio::signal::unix::{signal, SignalKind};
    use tokio::time::{timeout, Duration};

    const BOUND: Duration = Duration::from_secs(10);

    let runtime_guard = BackgroundRuntime(Some(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap(),
    ));
    let control_runtime = runtime_guard.0.as_ref().unwrap().handle().clone();

    let (store, _inner) = SharedMemoryStore::new();
    let hooks = Arc::clone(&store.hooks);
    let (factory_state, control_plane) = factory_state_with_store(store);
    for id in ["key-1", "key-2", "key-3"] {
        control_plane
            .mint_key(&TenantId::new("tenant-a"), &KeyId::new(id))
            .unwrap();
    }
    let (_server, addr) = control_runtime
        .spawn(start_full(
            snapshot_with_secret(),
            None,
            factory_state,
            Some(ADMIN_TOKEN.to_string()),
        ))
        .await
        .unwrap();

    let (registered_tx, registered_rx) = tokio::sync::oneshot::channel();
    let (sigterm_tx, sigterm_rx) = tokio::sync::oneshot::channel();
    control_runtime.spawn(async move {
        let mut terminate = signal(SignalKind::terminate()).expect("install the SIGTERM handler");
        let _ = registered_tx.send(());
        terminate.recv().await;
        let _ = sigterm_tx.send(());
    });
    registered_rx.await.unwrap();

    let gate = Arc::new(Gate::default());
    let _open_on_drop = OpenOnDrop(Arc::clone(&gate));
    {
        let gate = Arc::clone(&gate);
        *hooks.before_revoke.lock().unwrap() = Some(Arc::new(move || gate.wait()));
    }
    let revokes: Vec<_> = ["key-1", "key-2", "key-3"]
        .into_iter()
        .map(|id| {
            tokio::spawn(async move {
                request(
                    addr,
                    "DELETE",
                    &format!("/keys/{id}"),
                    Some(ADMIN_TOKEN),
                    "",
                )
                .await
            })
        })
        .collect();
    timeout(BOUND, async {
        while gate.entered.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("a revoke must reach the store and wait there");

    let ready = timeout(BOUND, get(addr, "/ready")).await;
    assert_eq!(
        ready.map(|(status, _)| status).ok(),
        Some(StatusCode::OK),
        "/ready must answer while admin writes wait on the store"
    );

    let status = std::process::Command::new("kill")
        .args(["-TERM", &std::process::id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(
        timeout(BOUND, sigterm_rx).await.is_ok(),
        "SIGTERM must be handled while admin writes wait on the store"
    );

    gate.open();
    for revoke in revokes {
        let (status, _, body) = timeout(BOUND, revoke).await.unwrap().unwrap();
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    }
}
