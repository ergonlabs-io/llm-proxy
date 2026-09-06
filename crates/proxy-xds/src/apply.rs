//! WP-20 increment 4b-ii: turning an ACCEPTED `DiscoveryResponse` into a
//! published [`ConfigSnapshot`] (S8).
//!
//! Everything above this module deliberately stopped short of this:
//! `store.rs` is "pure logic. No protobuf, no I/O, no `proxy-config` edge";
//! `client.rs`'s validator "never reads `resources` -- only `type_url`,
//! `version_info` and `nonce`". Assembling the actual snapshot is why THIS
//! module is the one that finally takes the `proxy-config` edge this crate's
//! own `Cargo.toml` comment has been predicting since increment 3a.
//!
//! # The pipeline this encodes, quoting `subscription.rs`'s own doc
//!
//! > validate all resources -> all-or-nothing accept -> apply -> ACK(...);
//! > any failure -> NACK(...) and discard entire response.
//!
//! Six consequences that are easy to get subtly wrong, and most have their
//! own test in `tests/apply.rs`:
//!
//! 1. **All-or-nothing, per S8.** Every resource in a response is lowered to
//!    IR before ANY of them touches a [`SotwSet`]. One failure discards the
//!    whole response -- no partial [`SotwSet::apply`], no snapshot, no
//!    publish call, and [`ResourceApplier::current`] does not move.
//! 2. **A resource's name comes from the decoded IR, not the `Any`.**
//!    `google.protobuf.Any` carries no name field, so this module decodes a
//!    resource TWICE on the happy path: once, best-effort, just to label an
//!    error's dotted path before the real decode runs; once for real inside
//!    [`proxy_config::lower_dynamic_cluster`] /
//!    [`proxy_config::lower_dynamic_listener`], whose returned IR carries
//!    `.name`.
//! 3. **The `unchanged`/`updated` distinction a [`SotwSet`] needs is decided
//!    over the raw resource bytes, not the IR** -- see [`Entry`]'s doc for
//!    why that is safe.
//! 4. **A response that changes nothing publishes nothing.** Not a new
//!    snapshot, not a version bump -- a control plane re-sending an
//!    identical resource set must not churn every worker on the other end of
//!    [`Publish`]. The response is still `Accept`ed; it is simply a no-op.
//! 5. **A name shadowed by a static resource is loud, not silent.** A
//!    `tracing::warn!` names the resource and says the static definition
//!    keeps serving -- `internal-docs/envoy-divergences.md` already records
//!    this as a deliberate divergence from Envoy's own silence here.
//! 6. **RDS and EDS are refused by name**, not silently ignored (ground
//!    rule #1's shape). **Both belong to WP-21, not to WP-20** -- corrected
//!    2026-09-06, because an earlier note here claimed RDS for WP-20's own
//!    increment 5 and that was wrong. The IR has no way to express either
//!    dependency: a `HttpConnectionManagerConfig` carries its route table
//!    inline as an `Arc<RouteTable>` with no by-name variant, and there is no
//!    `Eds` discovery type. `proxy-config`'s own lowering has said so all
//!    along -- an HCM using `rds` is refused with "RDS is not implemented yet
//!    (WP-21)". Applying either here would mean inventing an IR shape whose
//!    warming rules WP-21 owns.
//!
//! # Ordering is `SotwSet::apply`'s job, not this module's
//!
//! S8's `CDS -> EDS -> LDS -> RDS` apply ordering lives in
//! `SotwSet`/`store.rs`'s own doc; this module does not sequence anything
//! across types -- it maintains one independent [`SotwSet`] per type and
//! only ever touches one of them per call, driven by the response's own
//! `type_url`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use prost::Message;
use proxy_api::envoy::config::cluster::v3::Cluster as ClusterProto;
use proxy_api::envoy::config::listener::v3::Listener as ListenerProto;
use proxy_api::envoy::service::discovery::v3::DiscoveryResponse;
use proxy_config::ir::{ClusterConfig, ConfigSnapshot, ListenerConfig, SnapshotVersion};
use proxy_config::{lower_dynamic_cluster, lower_dynamic_listener};

use crate::client::ResponseHandler;
use crate::store::{ApplyError, ApplyOutcome, SetSemantics, SotwSet};
use crate::subscription::Verdict;

/// Full `type_url` a CDS `DiscoveryResponse` carries -- matches the constant
/// `testing/controlplane`'s own selftest uses (`CLUSTER_TYPE_URL`).
const CDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
/// Full `type_url` an LDS `DiscoveryResponse` carries.
const LDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.listener.v3.Listener";
/// RDS's `type_url` -- named so an incoming response is refused by name
/// (ground rule #1) rather than falling into the generic "unknown" branch.
const RDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.route.v3.RouteConfiguration";
/// EDS's `type_url` -- same reasoning as [`RDS_TYPE_URL`].
const EDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment";

/// Where a newly assembled snapshot goes once every resource in a response
/// has lowered cleanly.
///
/// Rust note: same shape as [`crate::client::Sleep`] -- a boxed `FnMut`
/// returning a boxed future rather than an `async fn` in a struct field,
/// because the closure has to live in a struct field and be called from
/// behind `&mut self`, and `Pin<Box<dyn Future>>` is the ordinary way to name
/// "some future I will not spell out" there. It is a future (not a plain
/// synchronous callback, as increment 4b-ii first had it) because the real
/// `ConfigPublisher::publish` it wraps runs LAST in
/// `crates/proxy/src/main.rs::reload`, after
/// `ClusterManager::update_from_snapshot`'s own await -- this seam has to be
/// able to await too, or that ordering could never reach it. This is an
/// injected callback, not a dependency on `proxy-core`'s `ConfigPublisher`
/// directly, so this crate never pulls in the worker runtime; wiring the real
/// one in is `crates/proxy/src/main.rs`'s job, not this module's.
pub type Publish =
    Box<dyn FnMut(Arc<ConfigSnapshot>) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>;

/// One dynamically-held resource: the raw bytes it arrived as, plus the IR
/// [`lower_dynamic_cluster`] / [`lower_dynamic_listener`] produced from them.
///
/// Rust note: `PartialEq` is hand-written below instead of derived, and
/// compares ONLY `raw` -- `ir` is deliberately excluded. That is safe only
/// because `ir` is a pure function of `raw`: lowering has no input besides
/// the bytes and a `path` used purely to word an error message, so equal
/// bytes already implies an equal IR, and there is nothing for the ignored
/// field to disagree about. This is also what Envoy itself does -- it hashes
/// the resource rather than diffing the parsed config. Neither `ClusterConfig`
/// nor `ListenerConfig` derives `PartialEq` (ground rule note: adding it
/// across that whole tree is out of this increment's scope), which is the
/// other reason this compares bytes instead. A hand-written `PartialEq` that
/// silently ignores a field is a footgun anywhere else in this codebase --
/// safe here only because of the invariant above, which is why it is written
/// down rather than left for whoever next touches `ir` to rediscover.
#[derive(Debug, Clone)]
struct Entry<T> {
    raw: Vec<u8>,
    ir: Arc<T>,
}

impl<T> PartialEq for Entry<T> {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

/// Best-effort dotted-path root for an error raised while lowering CDS
/// resource `index`: `cds.clusters[<name>]` once the bytes decode far enough
/// to read a name, `cds.clusters[<index>]` otherwise. This is only ever a
/// label -- if the bytes are not valid `Cluster` wire format at all,
/// [`lower_dynamic_cluster`] reports the real "cannot decode" reason itself.
fn cds_path(any: &prost_types::Any, index: usize) -> String {
    match ClusterProto::decode(any.value.as_slice()) {
        Ok(c) if !c.name.is_empty() => format!("cds.clusters[{}]", c.name),
        _ => format!("cds.clusters[{index}]"),
    }
}

/// Same idea as [`cds_path`], for LDS.
fn lds_path(any: &prost_types::Any, index: usize) -> String {
    match ListenerProto::decode(any.value.as_slice()) {
        Ok(l) if !l.name.is_empty() => format!("lds.listeners[{}]", l.name),
        _ => format!("lds.listeners[{index}]"),
    }
}

/// Turns accepted `DiscoveryResponse`s into published [`ConfigSnapshot`]s.
///
/// Holds one independent [`SotwSet`] per resource type (CDS, LDS), each
/// seeded at construction with `base`'s own listener/cluster names as its
/// immune static set (`store.rs` rule 3), plus the most recently published
/// snapshot so a no-op response (rule 4 above) has something to leave
/// untouched.
pub struct ResourceApplier {
    /// The static bootstrap snapshot. Never mutated; every published
    /// snapshot's `admin`/`tracing`/`ads`/`routes`/`secrets` and static
    /// listener/cluster entries are copied from here unchanged.
    base: Arc<ConfigSnapshot>,
    clusters: SotwSet<Entry<ClusterConfig>>,
    listeners: SotwSet<Entry<ListenerConfig>>,
    /// The snapshot most recently published -- `base` itself until the first
    /// response that actually changes something.
    current: Arc<ConfigSnapshot>,
    publish: Publish,
}

impl ResourceApplier {
    /// `base` is the static bootstrap snapshot. Its listener and cluster
    /// names become the immune static name sets (`store.rs` rule 3).
    pub fn new(base: Arc<ConfigSnapshot>, publish: Publish) -> Self {
        let static_clusters = base.clusters.keys().cloned().collect();
        let static_listeners = base.listeners.keys().cloned().collect();
        Self {
            clusters: SotwSet::new(SetSemantics::FullState, static_clusters),
            listeners: SotwSet::new(SetSemantics::FullState, static_listeners),
            current: Arc::clone(&base),
            base,
            publish,
        }
    }

    /// The snapshot most recently published, for tests and for
    /// `/config_dump`.
    pub fn current(&self) -> &Arc<ConfigSnapshot> {
        &self.current
    }

    /// Decode, validate, apply and publish one response. `Accept` iff every
    /// resource in it lowered cleanly.
    ///
    /// Routing is by the response's own `type_url` (rule 6 above): CDS and
    /// LDS are the only types this increment applies, and any other
    /// `type_url` -- including RDS and EDS, both real xDS types just not
    /// this increment's job -- is refused by name rather than silently
    /// ignored (ground rule #1).
    ///
    /// `async` since increment 4d-i: publishing (below, via [`Publish`]) can
    /// now await, and this is the method that awaits it, so
    /// [`AdsClient::run_once`](crate::client::AdsClient::run_once) can finish
    /// applying a response before it sends that response's ACK.
    pub async fn on_response(&mut self, resp: &DiscoveryResponse) -> Verdict {
        match resp.type_url.as_str() {
            CDS_TYPE_URL => self.on_cds_response(resp).await,
            LDS_TYPE_URL => self.on_lds_response(resp).await,
            RDS_TYPE_URL => Verdict::Reject(format!(
                "RDS (`{RDS_TYPE_URL}`) is not applied: a listener references its route table \
                 inline, and the by-name variant plus the warming rules that go with it are \
                 WP-21's"
            )),
            EDS_TYPE_URL => Verdict::Reject(format!(
                "EDS (`{EDS_TYPE_URL}`) is not applied by this increment -- endpoint discovery \
                 is WP-21's"
            )),
            other => Verdict::Reject(format!("unknown ADS type_url `{other}`")),
        }
    }

    async fn on_cds_response(&mut self, resp: &DiscoveryResponse) -> Verdict {
        let mut pairs = Vec::with_capacity(resp.resources.len());
        for (index, any) in resp.resources.iter().enumerate() {
            let path = cds_path(any, index);
            let ir = match lower_dynamic_cluster(any, &path) {
                Ok(ir) => ir,
                // Rule 1: bail out before touching `self.clusters` at all --
                // nothing lowered so far is applied.
                Err(err) => return Verdict::Reject(err.to_string()),
            };
            let name = ir.name.clone();
            pairs.push((
                name,
                Entry {
                    raw: any.value.clone(),
                    ir: Arc::new(ir),
                },
            ));
        }
        let outcome = match self.clusters.apply(pairs) {
            Ok(outcome) => outcome,
            Err(ApplyError::DuplicateName(name)) => {
                return Verdict::Reject(format!(
                    "CDS response named cluster `{name}` more than once"
                ));
            }
        };
        self.finish(outcome, "cluster").await
    }

    async fn on_lds_response(&mut self, resp: &DiscoveryResponse) -> Verdict {
        let mut pairs = Vec::with_capacity(resp.resources.len());
        for (index, any) in resp.resources.iter().enumerate() {
            let path = lds_path(any, index);
            let ir = match lower_dynamic_listener(any, &path) {
                Ok(ir) => ir,
                Err(err) => return Verdict::Reject(err.to_string()),
            };
            let name = ir.name.clone();
            pairs.push((
                name,
                Entry {
                    raw: any.value.clone(),
                    ir: Arc::new(ir),
                },
            ));
        }
        let outcome = match self.listeners.apply(pairs) {
            Ok(outcome) => outcome,
            Err(ApplyError::DuplicateName(name)) => {
                return Verdict::Reject(format!(
                    "LDS response named listener `{name}` more than once"
                ));
            }
        };
        self.finish(outcome, "listener").await
    }

    /// Common tail of both `on_*_response` methods: warn on anything shadowed
    /// (rule 5), publish a fresh snapshot iff something actually changed
    /// (rule 4), and accept either way -- a `SotwSet::apply` that ran at all
    /// already means every resource in the response lowered cleanly.
    async fn finish(&mut self, outcome: ApplyOutcome, kind: &str) -> Verdict {
        for name in &outcome.shadowed_by_static {
            tracing::warn!(
                resource = %name,
                kind,
                "dynamic {kind} `{name}` shares a name with a statically-configured one; the \
                 static definition keeps serving and this xDS update is refused for that name"
            );
        }

        let changed =
            !outcome.added.is_empty() || !outcome.updated.is_empty() || !outcome.removed.is_empty();
        if changed {
            let snapshot = self.assemble_snapshot();
            (self.publish)(Arc::clone(&snapshot)).await;
            self.current = snapshot;
        }
        Verdict::Accept
    }

    /// Build a fresh snapshot: the dynamic sets' current entries merged over
    /// `base`, version bumped by one from `current` (the last one actually
    /// published, so a no-op response leaves no gap in the sequence).
    ///
    /// The merge itself is [`ConfigSnapshot::with_dynamic_resources`], in
    /// `proxy-config`, and deliberately not a struct literal here: a struct
    /// literal in a runtime crate names every field of `ConfigSnapshot`, which
    /// would make all of them read as consumed by
    /// `crates/proxy-config/tests/ir_readership.rs`'s scan whether or not
    /// anything acts on them. That test's own module doc names this as the
    /// failure mode it exists to prevent. See the method's doc.
    fn assemble_snapshot(&self) -> Arc<ConfigSnapshot> {
        let listeners = self
            .listeners
            .names()
            .into_iter()
            .map(|name| {
                let entry = self
                    .listeners
                    .get(name)
                    .expect("a name SotwSet::names() just returned must be present in the set");
                (name.to_string(), Arc::clone(&entry.ir))
            })
            .collect();
        let clusters = self
            .clusters
            .names()
            .into_iter()
            .map(|name| {
                let entry = self
                    .clusters
                    .get(name)
                    .expect("a name SotwSet::names() just returned must be present in the set");
                (name.to_string(), Arc::clone(&entry.ir))
            })
            .collect();

        Arc::new(self.base.with_dynamic_resources(
            listeners,
            clusters,
            SnapshotVersion(self.current.version.0 + 1),
        ))
    }
}

/// `ResourceApplier` IS the real [`ResponseHandler`] -- there is no adapter
/// step (increment 4b-ii's `into_validator` filled that role for the old
/// synchronous [`crate::client::Validator`] seam and is gone; a caller now
/// passes a `ResourceApplier` to [`crate::client::AdsClient::run`] /
/// `run_once` directly).
impl ResponseHandler for ResourceApplier {
    fn handle(&mut self, resp: &DiscoveryResponse) -> impl Future<Output = Verdict> + Send {
        self.on_response(resp)
    }
}
