//! `GET /v1/usage` with a shared store: a control-side read of the window
//! rows (ADR-0006 addendum §4).
//!
//! Admission never reads the store. This endpoint admits nothing, so with a
//! shared store it reports the fleet totals the store holds instead of this
//! replica's counters: a replica holds a bucket only for what it has served,
//! and its local view would report a route another replica served as absent.
//! With an in-memory or persistent store there is one replica, and its local
//! counters are the exact answer; [`UsageReader`] is not built at all.
//!
//! The worker never does the I/O. It hands the read to [`UsageReader`]'s
//! thread, which makes the store call, and waits on a oneshot channel. Reads
//! for one tenant, dimension and window coalesce onto one store round trip
//! while it is in flight, and a successful answer is reused for
//! [`USAGE_READ_REUSE`], so callers cannot multiply load on the store however
//! often they call the endpoint. A failed read is not reused: the next call
//! retries, and coalescing still bounds it to one read in flight per tenant.
//!
//! The answer is the store's, so it lags this replica's own undelivered
//! counts by up to one reconcile interval (about a second).
//!
//! Store rows are point reads keyed by subject, so the read needs the route
//! names to ask for. The HTTP connection manager publishes its route table's
//! names in [`ChainRouteNames`] on every chain build, which follows route
//! updates.

use std::collections::{BTreeSet, HashMap};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use proxy_config::ir::RouteTable;
use tokio::sync::oneshot;

use crate::control::{ControlPlaneStore, StoreError, WindowDimension, WindowKey, WindowRow};
use crate::token_limit::LimitKey;

/// How long one successful answer is reused for the same tenant and window
/// (addendum §4: about one second).
pub const USAGE_READ_REUSE: Duration = Duration::from_secs(1);

/// How long the filter holds a usage request for the store's answer before
/// it answers 503 (addendum §4: about two seconds).
pub const USAGE_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// The least time between two warnings about failed usage reads.
const READ_WARN_INTERVAL: Duration = Duration::from_secs(60);

/// Totals for one tenant by row label (a route name, or the label the filter
/// gives a route-independent rule), sorted by label. Rows the store holds no
/// count for are left out, as the local view leaves out routes with no
/// bucket.
pub type RouteTotals = Arc<[(String, u64)]>;

/// What a usage read resolves to.
pub type UsageAnswer = Result<RouteTotals, StoreError>;

/// The `SharedFactoryState` key a chain's [`ChainRouteNames`] lives under,
/// next to the chain's other singletons.
pub const ROUTE_NAMES_KEY: &str = "llmproxy.internal.route_names";

/// The route names of one HTTP filter chain's current route table. The
/// connection manager publishes them on every build of the chain (an RDS
/// update rebuilds it), and the token limiter reads them when it builds a
/// shared-store usage read.
#[derive(Default)]
pub struct ChainRouteNames {
    names: ArcSwap<Vec<String>>,
}

impl ChainRouteNames {
    /// Replace the names with those of `table`. An unnamed route counts
    /// under the empty name, as the token limiter buckets it.
    pub fn publish_from(&self, table: &RouteTable) {
        self.publish(
            table
                .virtual_hosts
                .iter()
                .flat_map(|vhost| vhost.routes.iter())
                .map(|route| route.name.clone().unwrap_or_default()),
        );
    }

    /// Replace the names, sorted and without duplicates.
    pub fn publish(&self, names: impl IntoIterator<Item = String>) {
        let names: BTreeSet<String> = names.into_iter().collect();
        self.names.store(Arc::new(names.into_iter().collect()));
    }

    pub fn load(&self) -> Arc<Vec<String>> {
        self.names.load_full()
    }
}

/// One read: the tenant it answers for and the labelled rows it reads. Two
/// requests for the same rows share a read in flight and a reused answer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ReadKey {
    tenant: String,
    rows: Vec<(String, WindowRow)>,
}

enum Entry {
    /// A store read is running; everyone waiting on it.
    InFlight(Vec<oneshot::Sender<UsageAnswer>>),
    /// The last successful answer and when it arrived.
    Ready { at: Instant, totals: RouteTotals },
}

struct Job {
    key: ReadKey,
}

struct Shared {
    scope: String,
    store: Arc<dyn ControlPlaneStore>,
    entries: Mutex<HashMap<ReadKey, Entry>>,
    last_warn: Mutex<Option<Instant>>,
}

/// Reads per-route window totals for one tenant from a shared store, off the
/// worker. See the module doc.
pub struct UsageReader {
    shared: Arc<Shared>,
    jobs: mpsc::Sender<Job>,
}

impl UsageReader {
    /// `scope` is the window counters' scope, so the read names the same
    /// rows the flusher writes. Starts the reader thread, which exits when
    /// the reader is dropped and its current read, if any, returns.
    pub fn new(scope: String, store: Arc<dyn ControlPlaneStore>) -> Self {
        let shared = Arc::new(Shared {
            scope,
            store,
            entries: Mutex::new(HashMap::new()),
            last_warn: Mutex::new(None),
        });
        let (jobs, inbox) = mpsc::channel();
        let thread_shared = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("usage-reader".to_string())
            .spawn(move || run(&thread_shared, &inbox))
            .expect("spawning the usage reader thread");
        UsageReader { shared, jobs }
    }

    /// Ask for `tenant`'s totals on `routes` for `dimension` in `window`.
    /// Answers at once from an answer younger than [`USAGE_READ_REUSE`] as of
    /// `now`, joins a read already in flight, or starts one. Never blocks on
    /// the store.
    pub fn read(
        &self,
        tenant: &str,
        dimension: WindowDimension,
        window: WindowKey,
        routes: Vec<String>,
        now: Instant,
    ) -> oneshot::Receiver<UsageAnswer> {
        let routes: BTreeSet<String> = routes.into_iter().collect();
        let rows = routes
            .into_iter()
            .map(|route| {
                let row = WindowRow {
                    subject: LimitKey::for_tenant(&route, tenant).to_string(),
                    dimension,
                    window,
                };
                (route, row)
            })
            .collect();
        self.read_rows(tenant, rows, now)
    }

    /// Ask for `tenant`'s totals on labelled `rows`, which may mix
    /// dimensions and windows. Same reuse and coalescing as [`Self::read`].
    pub fn read_rows(
        &self,
        tenant: &str,
        rows: Vec<(String, WindowRow)>,
        now: Instant,
    ) -> oneshot::Receiver<UsageAnswer> {
        let (tx, rx) = oneshot::channel();
        let key = ReadKey {
            tenant: tenant.to_string(),
            rows,
        };
        {
            let mut entries = self.shared.lock_entries();
            entries.retain(|_, entry| match entry {
                Entry::InFlight(_) => true,
                Entry::Ready { at, .. } => now.saturating_duration_since(*at) < USAGE_READ_REUSE,
            });
            match entries.get_mut(&key) {
                Some(Entry::Ready { totals, .. }) => {
                    let _ = tx.send(Ok(Arc::clone(totals)));
                    return rx;
                }
                Some(Entry::InFlight(waiters)) => {
                    // A waiter that gave up (timed out, or its stream ended)
                    // has dropped its receiver; dropping its sender keeps a
                    // hung read from collecting every caller since.
                    waiters.retain(|waiter| !waiter.is_closed());
                    waiters.push(tx);
                    return rx;
                }
                None => {
                    entries.insert(key.clone(), Entry::InFlight(vec![tx]));
                }
            }
        }
        if let Err(mpsc::SendError(job)) = self.jobs.send(Job { key }) {
            self.shared.complete(
                &job.key,
                Err(StoreError::Unavailable(
                    "the usage reader has stopped".into(),
                )),
            );
        }
        rx
    }
}

fn run(shared: &Shared, inbox: &mpsc::Receiver<Job>) {
    while let Ok(job) = inbox.recv() {
        let answer = shared.read_store(&job);
        if let Err(e) = &answer {
            shared.warn_failed(e);
        }
        shared.complete(&job.key, answer);
    }
}

impl Shared {
    fn lock_entries(&self) -> std::sync::MutexGuard<'_, HashMap<ReadKey, Entry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn read_store(&self, job: &Job) -> UsageAnswer {
        let rows: Vec<WindowRow> = job.key.rows.iter().map(|(_, row)| row.clone()).collect();
        let results = self.store.load_window_batch(&self.scope, &rows);
        let mut totals = Vec::new();
        for ((label, _), result) in job.key.rows.iter().zip(results) {
            let used = result?;
            if used > 0 {
                totals.push((label.clone(), used));
            }
        }
        totals.sort();
        Ok(totals.into())
    }

    /// Hand `answer` to everyone waiting on `key`, and keep it for reuse if
    /// it succeeded.
    fn complete(&self, key: &ReadKey, answer: UsageAnswer) {
        let waiters = {
            let mut entries = self.lock_entries();
            let waiters = match entries.remove(key) {
                Some(Entry::InFlight(waiters)) => waiters,
                _ => Vec::new(),
            };
            if let Ok(totals) = &answer {
                entries.insert(
                    key.clone(),
                    Entry::Ready {
                        at: Instant::now(),
                        totals: Arc::clone(totals),
                    },
                );
            }
            waiters
        };
        for waiter in waiters {
            let _ = waiter.send(answer.clone());
        }
    }

    /// The endpoint answers 503 when the store fails, so this is not a
    /// fail-open; the warning tells an operator why, at most once per
    /// [`READ_WARN_INTERVAL`].
    fn warn_failed(&self, error: &StoreError) {
        let now = Instant::now();
        let mut last = self
            .last_warn
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if last.is_some_and(|at| now.saturating_duration_since(at) < READ_WARN_INTERVAL) {
            return;
        }
        *last = Some(now);
        drop(last);
        tracing::warn!(error = %error, scope = %self.scope,
            "llmproxy.token_limit: GET /v1/usage could not read the shared store; answering 503");
    }
}

#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::unwrap_used)] // Test support may panic; see AGENTS.md "Rust style".
pub mod test_store {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};

    use crate::auth::{KeyId, TenantId};
    use crate::control::{
        ControlPlaneStore, FlushToken, InMemoryControlPlaneStore, LimitPolicy, StoreError,
        StoredControlPlane, StoredKey, WindowDelta, WindowRow,
    };
    use crate::model_authz::ModelAccess;
    use crate::spend::{PeriodKey, TenantBudget};

    /// Wraps an in-memory store: counts window reads, can fail them, and can
    /// hold them until released, to stand in for a slow or broken Redis. It
    /// reports itself shared, as the store it stands in for is. Clones are
    /// handles on one store, as replicas' connections are on one Redis.
    #[derive(Clone, Default)]
    pub struct ProbeStore {
        inner: Arc<InMemoryControlPlaneStore>,
        pub reads: Arc<AtomicUsize>,
        pub fail: Arc<AtomicBool>,
        held: Arc<(Mutex<bool>, Condvar)>,
    }

    impl ProbeStore {
        pub fn hold(&self) {
            *self.held.0.lock().unwrap() = true;
        }

        pub fn release(&self) {
            *self.held.0.lock().unwrap() = false;
            self.held.1.notify_all();
        }
    }

    impl ControlPlaneStore for ProbeStore {
        fn is_shared(&self) -> bool {
            true
        }
        fn add_window_batch(
            &self,
            scope: &str,
            node_id: &str,
            rows: &[WindowDelta<'_>],
        ) -> Vec<Result<u64, StoreError>> {
            self.inner.add_window_batch(scope, node_id, rows)
        }
        fn last_window_seq_batch(
            &self,
            scope: &str,
            node_id: &str,
            rows: &[WindowRow],
        ) -> Vec<Result<u64, StoreError>> {
            self.inner.last_window_seq_batch(scope, node_id, rows)
        }
        fn load_window_batch(
            &self,
            scope: &str,
            rows: &[WindowRow],
        ) -> Vec<Result<u64, StoreError>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            let mut held = self.held.0.lock().unwrap();
            while *held {
                held = self.held.1.wait(held).unwrap();
            }
            drop(held);
            if self.fail.load(Ordering::SeqCst) {
                return rows
                    .iter()
                    .map(|_| Err(StoreError::Unavailable("probe".into())))
                    .collect();
            }
            self.inner.load_window_batch(scope, rows)
        }
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
        fn put_key(&self, rec: &StoredKey) -> Result<(), StoreError> {
            self.inner.put_key(rec)
        }
        fn revoke_key(&self, key_id: &KeyId) -> Result<(), StoreError> {
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
        fn add_spend(
            &self,
            stat_prefix: &str,
            tenant: &TenantId,
            period: &PeriodKey,
            delta_micros: u64,
            token: FlushToken<'_>,
        ) -> Result<u64, StoreError> {
            self.inner
                .add_spend(stat_prefix, tenant, period, delta_micros, token)
        }
        fn overwrite_spend(
            &self,
            stat_prefix: &str,
            tenant: &TenantId,
            period: &PeriodKey,
            total_micros: u64,
        ) -> Result<(), StoreError> {
            self.inner
                .overwrite_spend(stat_prefix, tenant, period, total_micros)
        }
        fn load_spend(
            &self,
            stat_prefix: &str,
            tenant: &TenantId,
            period: &PeriodKey,
        ) -> Result<u64, StoreError> {
            self.inner.load_spend(stat_prefix, tenant, period)
        }
        fn last_flush_seq(
            &self,
            stat_prefix: &str,
            tenant: &TenantId,
            period: &PeriodKey,
            node_id: &str,
        ) -> Result<u64, StoreError> {
            self.inner
                .last_flush_seq(stat_prefix, tenant, period, node_id)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::Ordering;

    use super::test_store::ProbeStore;
    use crate::control::WindowDelta;

    const SCOPE: &str = "ingress";

    /// The minute this test started in, fixed for the whole test so a
    /// minute boundary mid-test cannot split its rows: the in-memory store
    /// prunes only rows whose window ended more than the grace period ago,
    /// so a current window is needed but its exact value is not.
    fn window() -> WindowKey {
        static WINDOW: std::sync::OnceLock<WindowKey> = std::sync::OnceLock::new();
        *WINDOW.get_or_init(|| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            WindowKey::containing(now, 60)
        })
    }

    fn seed(store: &dyn ControlPlaneStore, route: &str, tenant: &str, total: u64, seq: u64) {
        let row = WindowRow {
            subject: LimitKey::for_tenant(route, tenant).to_string(),
            dimension: WindowDimension::TotalTokens,
            window: window(),
        };
        let results = store.add_window_batch(
            SCOPE,
            "seeder",
            &[WindowDelta {
                row: &row,
                delta: total,
                seq,
            }],
        );
        assert!(results[0].is_ok(), "{results:?}");
    }

    fn routes(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    fn answer(rx: oneshot::Receiver<UsageAnswer>) -> UsageAnswer {
        rx.blocking_recv().expect("the reader always answers")
    }

    #[test]
    fn a_read_reports_every_route_the_store_counted_and_leaves_out_the_rest() {
        let store = ProbeStore::default();
        seed(&store, "r2", "acme", 30, 1);
        seed(&store, "r1", "acme", 10, 1);
        seed(&store, "r1", "other", 99, 1);
        let reader = UsageReader::new(SCOPE.into(), Arc::new(store.clone()));

        let totals = answer(reader.read(
            "acme",
            WindowDimension::TotalTokens,
            window(),
            routes(&["r1", "r2", "r3", "r1"]),
            Instant::now(),
        ))
        .unwrap();

        assert_eq!(
            totals.as_ref(),
            &[("r1".to_string(), 10), ("r2".to_string(), 30)],
            "sorted by route, another tenant's row not read, an unused route left out"
        );
    }

    #[test]
    fn concurrent_reads_for_one_tenant_share_one_store_round_trip() {
        let store = ProbeStore::default();
        seed(&store, "r1", "acme", 10, 1);
        store.hold();
        let reader = UsageReader::new(SCOPE.into(), Arc::new(store.clone()));
        let now = Instant::now();
        let read = || {
            reader.read(
                "acme",
                WindowDimension::TotalTokens,
                window(),
                routes(&["r1"]),
                now,
            )
        };

        let waiting: Vec<_> = (0..5).map(|_| read()).collect();
        store.release();

        for rx in waiting {
            assert_eq!(answer(rx).unwrap().as_ref(), &[("r1".to_string(), 10)]);
        }
        assert_eq!(store.reads.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn an_answer_is_reused_for_a_second_and_then_read_again() {
        let store = ProbeStore::default();
        seed(&store, "r1", "acme", 10, 1);
        let reader = UsageReader::new(SCOPE.into(), Arc::new(store.clone()));
        let read = |now: Instant| {
            answer(reader.read(
                "acme",
                WindowDimension::TotalTokens,
                window(),
                routes(&["r1"]),
                now,
            ))
            .unwrap()
        };

        let first = read(Instant::now());
        seed(&store, "r1", "acme", 5, 2);
        let reused = read(Instant::now());
        let later = read(Instant::now() + USAGE_READ_REUSE);

        assert_eq!(first.as_ref(), &[("r1".to_string(), 10)]);
        assert_eq!(reused.as_ref(), &[("r1".to_string(), 10)]);
        assert_eq!(later.as_ref(), &[("r1".to_string(), 15)]);
        assert_eq!(store.reads.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_failed_read_reaches_every_waiter_and_is_not_reused() {
        let store = ProbeStore::default();
        seed(&store, "r1", "acme", 10, 1);
        store.fail.store(true, Ordering::SeqCst);
        let reader = UsageReader::new(SCOPE.into(), Arc::new(store.clone()));
        let now = Instant::now();
        let read = || {
            answer(reader.read(
                "acme",
                WindowDimension::TotalTokens,
                window(),
                routes(&["r1"]),
                now,
            ))
        };

        assert!(matches!(read(), Err(StoreError::Unavailable(_))));
        store.fail.store(false, Ordering::SeqCst);
        assert_eq!(read().unwrap().as_ref(), &[("r1".to_string(), 10)]);
        assert_eq!(store.reads.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_hung_read_does_not_keep_the_callers_that_gave_up() {
        let store = ProbeStore::default();
        store.hold();
        let reader = UsageReader::new(SCOPE.into(), Arc::new(store.clone()));
        let now = Instant::now();
        let read = || {
            reader.read(
                "acme",
                WindowDimension::TotalTokens,
                window(),
                routes(&["r1"]),
                now,
            )
        };
        for _ in 0..100 {
            drop(read());
        }
        let last = read();

        let waiting = match reader.shared.lock_entries().values().next() {
            Some(Entry::InFlight(waiters)) => waiters.len(),
            _ => panic!("the read is still in flight"),
        };
        assert_eq!(waiting, 1, "only the caller still waiting is kept");
        store.release();
        assert!(answer(last).unwrap().is_empty());
    }
}
