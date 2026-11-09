//! Declared tenant policy against the in-memory and redb stores: what a
//! reconcile creates, updates, deletes and leaves; how an admin write and a
//! hand-back move a row between owners; the revision order replicas share;
//! rows written before sources existed; and that declaring a policy never
//! makes the caller wait on the store.

use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use proxy_credentials::CredentialSource;

use super::*;
use crate::auth::{HmacSecret, KeySet};
use crate::control::{
    ControlPlane, ControlPlaneStore, InMemoryControlPlaneStore, RedbControlPlaneStore, StoreError,
    StoredControlPlane,
};
use crate::model_authz::ModelPattern;
use crate::spend::{MicroUsd, Period};

fn budget(micros: u64) -> TenantBudget {
    TenantBudget {
        max_micros: MicroUsd::from_micros(micros),
        period: Period::Monthly,
        credential_source: CredentialSource::Platform,
    }
}

fn limits(rpm: u64) -> LimitPolicy {
    LimitPolicy {
        requests_per_minute: Some(rpm),
        ..LimitPolicy::default()
    }
}

fn scoped(name: &str) -> ScopedBudget {
    ScopedBudget {
        name: name.to_owned(),
        max_micros: MicroUsd::from_micros(5),
        period: Period::Daily,
        credential_source: CredentialSource::Platform,
        models: vec![ModelPattern::new("gpt-4o*")],
        providers: Vec::new(),
        alert_at_percent: Vec::new(),
    }
}

fn only(models: &[&str]) -> ModelAccess {
    ModelAccess::Only(models.iter().map(|m| ModelPattern::new(*m)).collect())
}

fn tenant(id: &str) -> DeclaredTenant {
    DeclaredTenant {
        tenant: TenantId::new(id),
        policy: Some(only(&["gpt-4o"])),
        budget: Some(budget(100)),
        scoped_budgets: vec![scoped("cap")],
        limits: Some(limits(60)),
    }
}

fn applied(outcome: ReconcileOutcome) -> ReconcileReport {
    match outcome {
        ReconcileOutcome::Applied(report) => report,
        other => panic!("expected the reconcile to apply, got {other:?}"),
    }
}

fn temp_db_path(hint: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "llm-proxy-declared-test-{hint}-{}-{}.redb",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

/// Both stores that hold rows in this process, so each behaviour test runs
/// against the in-memory map and the redb encoding alike.
fn stores(hint: &str) -> Vec<(&'static str, Box<dyn ControlPlaneStore>)> {
    vec![
        ("in_memory", Box::new(InMemoryControlPlaneStore::new())),
        (
            "redb",
            Box::new(RedbControlPlaneStore::open(temp_db_path(hint)).unwrap()),
        ),
    ]
}

fn tenant_ids(loaded: &StoredControlPlane) -> Vec<&str> {
    let mut ids: Vec<&str> = loaded.tenants.iter().map(TenantId::as_str).collect();
    ids.sort_unstable();
    ids
}

#[test]
fn a_reconcile_creates_updates_and_deletes_file_rows_and_never_touches_admin_rows() {
    for (name, store) in stores("lifecycle") {
        // An operator made `ops` by hand, with a budget.
        store.create_tenant(&TenantId::new("ops")).unwrap();
        store
            .set_budget(&TenantId::new("ops"), Some(&budget(7)))
            .unwrap();

        let report = applied(
            store
                .reconcile_declared(&DeclaredPolicy::new(
                    1,
                    vec![tenant("acme"), tenant("beta")],
                ))
                .unwrap(),
        );
        assert_eq!(
            (report.written, report.deleted),
            (10, 0),
            "{name}: two tenants of five rows each are created"
        );
        let loaded = store.load().unwrap();
        assert_eq!(tenant_ids(&loaded), ["acme", "beta", "ops"], "{name}");
        assert_eq!(
            loaded.budgets[&TenantId::new("acme")],
            budget(100),
            "{name}"
        );
        assert_eq!(loaded.limits[&TenantId::new("beta")], limits(60), "{name}");
        assert_eq!(
            loaded.scoped_budgets[&TenantId::new("acme")],
            vec![scoped("cap")]
        );
        assert_eq!(loaded.policies[&TenantId::new("acme")], only(&["gpt-4o"]));

        // Revision 2 changes acme's budget, drops its limits, and removes beta.
        let mut acme = tenant("acme");
        acme.budget = Some(budget(200));
        acme.limits = None;
        let report = applied(
            store
                .reconcile_declared(&DeclaredPolicy::new(2, vec![acme]))
                .unwrap(),
        );
        assert_eq!(
            (report.written, report.deleted),
            (1, 6),
            "{name}: one update; acme's limits and beta's five rows go"
        );
        assert_eq!(report.removed_tenants, [TenantId::new("beta")], "{name}");
        let loaded = store.load().unwrap();
        assert_eq!(tenant_ids(&loaded), ["acme", "ops"], "{name}: beta is gone");
        assert_eq!(
            loaded.budgets[&TenantId::new("acme")],
            budget(200),
            "{name}"
        );
        assert!(
            !loaded.limits.contains_key(&TenantId::new("acme"))
                && !loaded.policies.contains_key(&TenantId::new("beta"))
                && !loaded.scoped_budgets.contains_key(&TenantId::new("beta")),
            "{name}: rows the file stopped declaring are deleted"
        );
        assert_eq!(
            loaded.budgets[&TenantId::new("ops")],
            budget(7),
            "{name}: the admin tenant the file never declared keeps its row"
        );

        // An empty block removes every file row and nothing else.
        applied(
            store
                .reconcile_declared(&DeclaredPolicy::new(3, vec![]))
                .unwrap(),
        );
        let loaded = store.load().unwrap();
        assert_eq!(tenant_ids(&loaded), ["ops"], "{name}");
        assert_eq!(
            loaded.budgets.len(),
            1,
            "{name}: only the admin budget is left"
        );
    }
}

#[test]
fn an_admin_write_takes_a_row_over_until_it_is_handed_back() {
    for (name, store) in stores("takeover") {
        let acme = TenantId::new("acme");
        applied(
            store
                .reconcile_declared(&DeclaredPolicy::new(1, vec![tenant("acme")]))
                .unwrap(),
        );

        // The emergency change: an admin raises the budget.
        store.set_budget(&acme, Some(&budget(999))).unwrap();

        let mut changed = tenant("acme");
        changed.budget = Some(budget(300));
        let report = applied(
            store
                .reconcile_declared(&DeclaredPolicy::new(2, vec![changed.clone()]))
                .unwrap(),
        );
        assert_eq!(
            report.shadowed,
            [ShadowedRow {
                tenant: acme.clone(),
                kind: RowKind::Budget,
            }],
            "{name}: exactly the admin-written row is shadowed"
        );
        assert_eq!(
            store.load().unwrap().budgets[&acme],
            budget(999),
            "{name}: the admin value wins over the file"
        );
        // Removing the tenant from the file leaves the admin row too.
        applied(
            store
                .reconcile_declared(&DeclaredPolicy::new(3, vec![]))
                .unwrap(),
        );
        assert_eq!(store.load().unwrap().budgets[&acme], budget(999), "{name}");
        applied(
            store
                .reconcile_declared(&DeclaredPolicy::new(4, vec![changed.clone()]))
                .unwrap(),
        );

        // Hand-back: the row is file-owned again and the next reconcile
        // applies the file value.
        assert_eq!(
            store.hand_back_to_file(&acme).unwrap(),
            [RowKind::Budget],
            "{name}: only the admin row is handed back"
        );
        let report = applied(
            store
                .reconcile_declared(&DeclaredPolicy::new(4, vec![changed]))
                .unwrap(),
        );
        assert!(report.shadowed.is_empty(), "{name}: {report:?}");
        assert_eq!(store.load().unwrap().budgets[&acme], budget(300), "{name}");
        assert!(
            store.hand_back_to_file(&acme).unwrap().is_empty(),
            "{name}: nothing is admin-owned any more"
        );
    }
}

#[test]
fn an_older_revision_is_refused_and_one_revision_cannot_carry_two_files() {
    for (name, store) in stores("revision") {
        applied(
            store
                .reconcile_declared(&DeclaredPolicy::new(5, vec![tenant("acme")]))
                .unwrap(),
        );
        let generation = store.policy_generation().unwrap();

        // A replica still on revision 4 restarts: it must not undo revision 5.
        assert_eq!(
            store
                .reconcile_declared(&DeclaredPolicy::new(4, vec![]))
                .unwrap(),
            ReconcileOutcome::StaleRevision { stored: 5 },
            "{name}"
        );
        // An edit that kept the revision.
        assert_eq!(
            store
                .reconcile_declared(&DeclaredPolicy::new(5, vec![tenant("beta")]))
                .unwrap(),
            ReconcileOutcome::RevisionConflict,
            "{name}"
        );
        assert_eq!(
            tenant_ids(&store.load().unwrap()),
            ["acme"],
            "{name}: a refused reconcile writes nothing"
        );
        assert_eq!(store.policy_generation().unwrap(), generation, "{name}");

        // The same file again changes no row, so replicas are not made to
        // rebuild; a newer revision applies.
        applied(
            store
                .reconcile_declared(&DeclaredPolicy::new(5, vec![tenant("acme")]))
                .unwrap(),
        );
        assert_eq!(
            store.policy_generation().unwrap(),
            generation,
            "{name}: an unchanged reconcile must not bump the generation"
        );
        applied(
            store
                .reconcile_declared(&DeclaredPolicy::new(6, vec![]))
                .unwrap(),
        );
        assert!(store.policy_generation().unwrap() > generation, "{name}");
    }
}

/// Rows written before rows had a source, as literal bytes in their old
/// formats, load unchanged and count as admin rows: the file never deletes
/// what an operator made by hand.
#[test]
fn rows_written_before_sources_existed_load_as_admin_rows() {
    let path = temp_db_path("legacy");
    {
        let db = redb::Database::create(&path).unwrap();
        let txn = db.begin_write().unwrap();
        let rows: [(&str, &str, &[u8]); 5] = [
            ("tenants", "acme", b""),
            ("policies", "acme", br#"{"Only":["gpt-4o"]}"#),
            (
                "budgets",
                "acme",
                br#"{"schema_version":2,"max_micros":100,"period":"Monthly","credential_source":"platform"}"#,
            ),
            (
                "budgets",
                "\u{1f}scoped-budgets:acme",
                br#"{"schema_version":3,"budgets":[{"name":"cap","max_micros":5,"period":"Daily","credential_source":"platform","models":["gpt-4o*"]}]}"#,
            ),
            (
                "limits",
                "acme",
                br#"{"schema_version":1,"tokens_per_minute":null,"requests_per_minute":60,"concurrent_streams":null}"#,
            ),
        ];
        for (table, key, value) in rows {
            let definition: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new(table);
            txn.open_table(definition)
                .unwrap()
                .insert(key, value)
                .unwrap();
        }
        txn.commit().unwrap();
    }
    let store = RedbControlPlaneStore::open(&path).unwrap();
    let loaded = store.load().unwrap();
    assert_eq!(tenant_ids(&loaded), ["acme"]);
    assert_eq!(loaded.policies[&TenantId::new("acme")], only(&["gpt-4o"]));
    assert_eq!(loaded.budgets[&TenantId::new("acme")], budget(100));
    assert_eq!(
        loaded.scoped_budgets[&TenantId::new("acme")],
        vec![scoped("cap")]
    );
    assert_eq!(loaded.limits[&TenantId::new("acme")], limits(60));

    let report = applied(
        store
            .reconcile_declared(&DeclaredPolicy::new(1, vec![]))
            .unwrap(),
    );
    assert_eq!(report.deleted, 0, "an empty file deletes no legacy row");
    let report = applied(
        store
            .reconcile_declared(&DeclaredPolicy::new(2, vec![tenant("acme")]))
            .unwrap(),
    );
    assert_eq!(
        report
            .shadowed
            .iter()
            .map(|row| row.kind)
            .collect::<Vec<_>>(),
        RowKind::ALL,
        "every legacy row is admin-owned, so the file shadows all five"
    );
}

/// The stored format: an admin row is byte-for-byte what a build before
/// sources wrote, so a store without file rows stays readable by it; a file
/// row carries `source` and a version that build refuses.
#[test]
fn only_file_rows_carry_a_source_and_a_bumped_version() {
    use crate::control::{
        encode_limits_row, encode_policy_row, encode_scoped_budgets_row, encode_tenant_budget_row,
        encode_tenant_row,
    };
    let text = |bytes: Vec<u8>| String::from_utf8(bytes).unwrap();
    assert_eq!(encode_tenant_row(RowSource::Admin), b"");
    assert_eq!(
        text(encode_policy_row(&only(&["gpt-4o"]), RowSource::Admin)),
        r#"{"Only":["gpt-4o"]}"#
    );
    let admin_budget = text(encode_tenant_budget_row(&budget(100), RowSource::Admin));
    assert!(
        admin_budget.starts_with(r#"{"schema_version":2,"#)
            && !admin_budget.contains("source\":\"file"),
        "{admin_budget}"
    );
    let admin_limits = text(encode_limits_row(&limits(60), RowSource::Admin));
    assert!(
        admin_limits.starts_with(r#"{"schema_version":1,"#) && !admin_limits.contains("\"source\""),
        "{admin_limits}"
    );
    let admin_scoped = text(encode_scoped_budgets_row(
        &[scoped("cap")],
        RowSource::Admin,
    ));
    assert!(
        admin_scoped.starts_with(r#"{"schema_version":3,"#) && !admin_scoped.contains("\"source\""),
        "{admin_scoped}"
    );

    for (row, version) in [
        (text(encode_tenant_row(RowSource::File)), 1),
        (
            text(encode_policy_row(&only(&["gpt-4o"]), RowSource::File)),
            2,
        ),
        (
            text(encode_tenant_budget_row(&budget(100), RowSource::File)),
            3,
        ),
        (text(encode_limits_row(&limits(60), RowSource::File)), 3),
        (
            text(encode_scoped_budgets_row(&[scoped("cap")], RowSource::File)),
            4,
        ),
    ] {
        assert!(
            row.contains(&format!(r#""schema_version":{version}"#))
                && row.contains(r#""source":"file""#),
            "a file row must carry its source and version {version}: {row}"
        );
    }
}

/// A store whose reconcile waits until the test lets it go, standing in for
/// a store slow to apply a large file.
struct GatedStore {
    inner: InMemoryControlPlaneStore,
    entered: Mutex<Option<mpsc::Sender<()>>>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl ControlPlaneStore for GatedStore {
    fn load(&self) -> Result<StoredControlPlane, StoreError> {
        self.inner.load()
    }
    fn policy_generation(&self) -> Result<u64, StoreError> {
        self.inner.policy_generation()
    }
    fn create_tenant(&self, tenant: &TenantId) -> Result<(), StoreError> {
        self.inner.create_tenant(tenant)
    }
    fn delete_tenant(&self, tenant: &TenantId) -> Result<(), StoreError> {
        self.inner.delete_tenant(tenant)
    }
    fn put_key(&self, rec: &crate::control::StoredKey) -> Result<(), StoreError> {
        self.inner.put_key(rec)
    }
    fn revoke_key(&self, key_id: &crate::auth::KeyId) -> Result<(), StoreError> {
        self.inner.revoke_key(key_id)
    }
    fn set_policy(&self, tenant: &TenantId, access: &ModelAccess) -> Result<(), StoreError> {
        self.inner.set_policy(tenant, access)
    }
    fn set_budget(
        &self,
        tenant: &TenantId,
        budget: Option<&TenantBudget>,
    ) -> Result<(), StoreError> {
        self.inner.set_budget(tenant, budget)
    }
    fn set_key_budget(
        &self,
        key_id: &crate::auth::KeyId,
        budget: Option<&crate::spend::KeyBudget>,
    ) -> Result<(), StoreError> {
        self.inner.set_key_budget(key_id, budget)
    }
    fn set_limits(
        &self,
        subject: &TenantId,
        limits: Option<&LimitPolicy>,
    ) -> Result<(), StoreError> {
        self.inner.set_limits(subject, limits)
    }
    fn reconcile_declared(
        &self,
        declared: &DeclaredPolicy,
    ) -> Result<ReconcileOutcome, StoreError> {
        if let Some(entered) = self.entered.lock().unwrap().take() {
            entered.send(()).unwrap();
        }
        self.release
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(30))
            .expect("the test releases the reconcile");
        self.inner.reconcile_declared(declared)
    }
    fn add_spend(
        &self,
        stat_prefix: &str,
        tenant: &TenantId,
        period: &crate::spend::PeriodKey,
        delta_micros: u64,
        token: crate::control::FlushToken<'_>,
    ) -> Result<u64, StoreError> {
        self.inner
            .add_spend(stat_prefix, tenant, period, delta_micros, token)
    }
    fn overwrite_spend(
        &self,
        stat_prefix: &str,
        tenant: &TenantId,
        period: &crate::spend::PeriodKey,
        micros: u64,
    ) -> Result<(), StoreError> {
        self.inner
            .overwrite_spend(stat_prefix, tenant, period, micros)
    }
    fn last_flush_seq(
        &self,
        stat_prefix: &str,
        tenant: &TenantId,
        period: &crate::spend::PeriodKey,
        node_id: &str,
    ) -> Result<u64, StoreError> {
        self.inner
            .last_flush_seq(stat_prefix, tenant, period, node_id)
    }
    fn load_spend(
        &self,
        stat_prefix: &str,
        tenant: &TenantId,
        period: &crate::spend::PeriodKey,
    ) -> Result<u64, StoreError> {
        self.inner.load_spend(stat_prefix, tenant, period)
    }
    fn add_window_batch(
        &self,
        scope: &str,
        node_id: &str,
        rows: &[crate::control::WindowDelta<'_>],
    ) -> Vec<Result<u64, StoreError>> {
        self.inner.add_window_batch(scope, node_id, rows)
    }
    fn last_window_seq_batch(
        &self,
        scope: &str,
        node_id: &str,
        rows: &[crate::control::WindowRow],
    ) -> Vec<Result<u64, StoreError>> {
        self.inner.last_window_seq_batch(scope, node_id, rows)
    }
    fn load_window_batch(
        &self,
        scope: &str,
        rows: &[crate::control::WindowRow],
    ) -> Vec<Result<u64, StoreError>> {
        self.inner.load_window_batch(scope, rows)
    }
}

/// A reload hands the new block to `declare` from a chain build, which runs
/// on a request worker. The call must return while the store is still
/// applying it, with the published snapshot still readable, and the new rows
/// must arrive through a republished snapshot once the store finishes.
#[test]
fn declaring_a_policy_returns_before_the_store_applies_it_and_publishes_after() {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let store = GatedStore {
        inner: InMemoryControlPlaneStore::new(),
        entered: Mutex::new(Some(entered_tx)),
        release: Mutex::new(release_rx),
    };
    let control = Arc::new(
        ControlPlane::new(Box::new(store), HmacSecret::new(b"secret"), KeySet::new()).unwrap(),
    );
    let snapshot = control.handle();
    let acme = TenantId::new("acme");

    let tenants = (0..2_000).map(|i| tenant(&format!("tenant-{i:04}")));
    control.declare(Some(Arc::new(DeclaredPolicy::new(
        1,
        tenants.chain([tenant("acme")]).collect(),
    ))));

    // `declare` has returned; the reconcile is now inside the store, blocked.
    entered_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the reconcile reaches the store on its own thread");
    assert!(
        !snapshot.load().policies.contains_key(acme.as_str()),
        "while the store is busy, readers keep the previous snapshot"
    );

    release_tx.send(()).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let published = snapshot.load();
        if let Some(policy) = published.policies.get(acme.as_str()) {
            assert_eq!(policy.budget, Some(budget(100)));
            assert_eq!(published.policies.len(), 2_001);
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the reconciled rows were never published"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
