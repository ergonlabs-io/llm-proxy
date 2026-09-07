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
//! 6. **RDS is refused by name**, not silently ignored (ground rule #1's
//!    shape); **EDS is applied, as of WP-21 increment 2b-ii.** RDS still
//!    belongs to WP-21's warming logic, uncorrected since 2026-09-06: a
//!    `HttpConnectionManagerConfig` carries its route table inline as an
//!    `Arc<RouteTable>` with no by-name variant, so applying an RDS response
//!    would mean inventing an IR shape whose warming rules are not this
//!    increment's to own. EDS had no such obstacle -- `EndpointIR` is already
//!    a plain `Vec`, not a listener-shaped dependency -- so `on_eds_response`
//!    lowers it and hands the result to an injected [`PublishEndpoints`] sink,
//!    the same seam-not-dependency shape [`Publish`] already uses for
//!    listeners and clusters.
//!
//! # Ordering is `SotwSet::apply`'s job, not this module's
//!
//! S8's `CDS -> EDS -> LDS -> RDS` apply ordering lives in
//! `SotwSet`/`store.rs`'s own doc; this module does not sequence anything
//! across types -- it maintains one independent [`SotwSet`] per type and
//! only ever touches one of them per call, driven by the response's own
//! `type_url`.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use prost::Message;
use proxy_api::envoy::config::cluster::v3::Cluster as ClusterProto;
use proxy_api::envoy::config::endpoint::v3::ClusterLoadAssignment as ClusterLoadAssignmentProto;
use proxy_api::envoy::config::listener::v3::Listener as ListenerProto;
use proxy_api::envoy::service::discovery::v3::DiscoveryResponse;
use proxy_config::ir::{
    ClusterConfig, ConfigSnapshot, EndpointIR, ListenerConfig, SnapshotVersion,
};
use proxy_config::{lower_dynamic_cluster, lower_dynamic_endpoints, lower_dynamic_listener};

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

/// Where a newly assembled EDS resource's endpoints go once they lower
/// cleanly -- WP-21 increment 2b-ii's counterpart to [`Publish`], mirroring
/// its shape and its reasoning (an injected callback, not a dependency on the
/// real sink, for the same reason: the real one is
/// `ClusterManager::accept_eds_update` in `proxy-cluster`, and this crate must
/// stay free of that edge, exactly as `apply.rs`'s own module doc says of
/// `proxy-config`).
///
/// Unlike `Publish`, this one returns `Result<(), String>`. Endpoints do not
/// go into a `ConfigSnapshot` at all -- they go straight to the cluster
/// manager, which is a fallible operation for real (a DNS-discovery cluster
/// fed EDS endpoints it cannot resolve, for instance), and an EDS response
/// whose endpoints cannot be installed must NACK, not silently ACK a change
/// that never actually took effect. `Publish`'s `ConfigSnapshot` write, by
/// contrast, cannot itself fail -- it is an in-memory swap -- so it has
/// nothing to report back.
pub type PublishEndpoints = Box<
    dyn FnMut(String, Vec<EndpointIR>) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>>
        + Send,
>;

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

/// Same idea as [`cds_path`], for EDS -- `cluster_name` is the assignment's
/// own name field (see [`lower_dynamic_endpoints`]'s doc for why that is not
/// necessarily any `Cluster.name`).
fn eds_path(any: &prost_types::Any, index: usize) -> String {
    match ClusterLoadAssignmentProto::decode(any.value.as_slice()) {
        Ok(la) if !la.cluster_name.is_empty() => format!("eds.endpoints[{}]", la.cluster_name),
        _ => format!("eds.endpoints[{index}]"),
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
    /// EDS's own set -- `PerName`, not `FullState`. S8 draws this line for a
    /// reason store.rs's own doc states directly: "SotW: LDS/CDS full-set
    /// semantics (absence = removal); EDS/RDS absence != removal." A
    /// `ClusterLoadAssignment` response only ever carries the load
    /// assignments a control plane feels like (re)declaring right now, not
    /// every EDS cluster subscribed to -- treating an absent one as a
    /// removal would depopulate a healthy cluster's endpoints the moment some
    /// unrelated one gets pushed.
    ///
    /// Its static-name set (below, at construction) is deliberately EMPTY,
    /// which is the subtle half of this: `store.rs` rule 3 exists so a
    /// dynamic resource cannot steal a name a bootstrap file already claimed,
    /// but an EDS resource name lives in a namespace of its own -- it is
    /// `EdsClusterConfig.service_name`, not any `Cluster.name` -- and an EDS
    /// cluster is *supposed* to be declared statically (in `base.clusters`)
    /// while being fed dynamically over this exact set. Seeding this with
    /// `base.clusters`' names, the way `clusters`/`listeners` seed theirs,
    /// would shadow precisely the case this increment exists to support: the
    /// primary one, a statically-declared `Cluster` whose `eds_cluster_config`
    /// names a resource this applier is meant to keep populated.
    endpoints: SotwSet<Entry<Vec<EndpointIR>>>,
    /// The snapshot most recently published -- `base` itself until the first
    /// response that actually changes something.
    current: Arc<ConfigSnapshot>,
    publish: Publish,
    /// Where accepted EDS endpoints go. `None` until
    /// [`ResourceApplier::with_endpoint_sink`] wires one -- until then, an
    /// EDS response is refused (see `on_eds_response`).
    endpoint_sink: Option<PublishEndpoints>,
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
            // Empty static-name set on purpose -- see the field's own doc.
            endpoints: SotwSet::new(SetSemantics::PerName, BTreeSet::new()),
            current: Arc::clone(&base),
            base,
            publish,
            endpoint_sink: None,
        }
    }

    /// Wire the sink accepted EDS endpoints are handed to. A consuming
    /// builder (`mut self` in, `Self` out) -- the same shape
    /// `AdsClient::with_node` uses -- rather than a new `new` parameter, so
    /// every existing caller and test of `ResourceApplier::new` keeps
    /// compiling unchanged. Without this, `on_eds_response` keeps refusing
    /// EDS by name (ground rule #1's shape) instead of silently no-op'ing.
    pub fn with_endpoint_sink(mut self, sink: PublishEndpoints) -> Self {
        self.endpoint_sink = Some(sink);
        self
    }

    /// The snapshot most recently published, for tests and for
    /// `/config_dump`.
    pub fn current(&self) -> &Arc<ConfigSnapshot> {
        &self.current
    }

    /// The EDS resource names this applier's current snapshot needs a live
    /// subscription for: every cluster in [`ResourceApplier::current`] --
    /// static or dynamic, either counts -- whose `eds_cluster_config` names
    /// one. `client.rs`'s pump asks for this via
    /// [`ResponseHandler::desired_names`] after every response, so accepting
    /// a CDS response that names a new EDS cluster is what causes the EDS
    /// subscription to widen to cover it (see this module's own doc for the
    /// ordering that makes that true).
    pub fn eds_resource_names(&self) -> BTreeSet<String> {
        self.current
            .clusters
            .values()
            .filter_map(|cluster| cluster.eds.as_ref().map(|eds| eds.service_name.clone()))
            .collect()
    }

    /// Decode, validate, apply and publish one response. `Accept` iff every
    /// resource in it lowered cleanly.
    ///
    /// Routing is by the response's own `type_url` (rule 6 above): CDS, LDS
    /// and EDS are applied; RDS -- a real xDS type, just not this
    /// increment's job -- and anything else are refused by name rather than
    /// silently ignored (ground rule #1).
    ///
    /// `async` since increment 4d-i: publishing (below, via [`Publish`]) can
    /// now await, and this is the method that awaits it, so
    /// [`AdsClient::run_once`](crate::client::AdsClient::run_once) can finish
    /// applying a response before it sends that response's ACK.
    pub async fn on_response(&mut self, resp: &DiscoveryResponse) -> Verdict {
        match resp.type_url.as_str() {
            CDS_TYPE_URL => self.on_cds_response(resp).await,
            LDS_TYPE_URL => self.on_lds_response(resp).await,
            EDS_TYPE_URL => self.on_eds_response(resp).await,
            RDS_TYPE_URL => Verdict::Reject(format!(
                "RDS (`{RDS_TYPE_URL}`) is not applied: a listener references its route table \
                 inline, and the by-name variant plus the warming rules that go with it are \
                 WP-21's"
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

    /// EDS has no `finish` call -- unlike CDS/LDS, an accepted endpoint
    /// update never touches `ConfigSnapshot` or `self.publish` (see
    /// `endpoints`'s own doc); it goes straight to the injected
    /// [`PublishEndpoints`] sink instead, once per name actually `added` or
    /// `updated` (never `unchanged` -- that suppression is the whole point of
    /// `Entry`'s byte comparison).
    async fn on_eds_response(&mut self, resp: &DiscoveryResponse) -> Verdict {
        let Some(sink) = self.endpoint_sink.as_mut() else {
            return Verdict::Reject(format!(
                "EDS (`{EDS_TYPE_URL}`) is not applied: this ResourceApplier has no endpoint \
                 sink wired -- see `ResourceApplier::with_endpoint_sink`"
            ));
        };

        let mut pairs = Vec::with_capacity(resp.resources.len());
        for (index, any) in resp.resources.iter().enumerate() {
            let path = eds_path(any, index);
            let (name, endpoints) = match lower_dynamic_endpoints(any, &path) {
                Ok(pair) => pair,
                // Rule 1 (all-or-nothing): bail out before touching
                // `self.endpoints` at all -- nothing lowered so far is
                // applied, and the sink is never called for this response.
                Err(err) => return Verdict::Reject(err.to_string()),
            };
            pairs.push((
                name,
                Entry {
                    raw: any.value.clone(),
                    ir: Arc::new(endpoints),
                },
            ));
        }

        let outcome = match self.endpoints.apply(pairs) {
            Ok(outcome) => outcome,
            Err(ApplyError::DuplicateName(name)) => {
                return Verdict::Reject(format!(
                    "EDS response named cluster load assignment `{name}` more than once"
                ));
            }
        };

        // `apply` above already recorded every added/updated name in the
        // store -- BEFORE the sink below has run. See `SotwSet::forget`'s own
        // doc for why that ordering needs a fix-up rather than being left
        // alone: this increment's chosen fix is (a), forgetting exactly the
        // names whose sink call failed, so a later retransmission of
        // identical bytes reads as `added` again instead of `unchanged` and
        // reaches the sink a second time. Names that succeeded stay recorded
        // -- there is no reason to make the sink redo work it already did.
        let mut failed = Vec::new();
        for name in outcome.added.iter().chain(outcome.updated.iter()) {
            let entry = self
                .endpoints
                .get(name)
                .expect("a name SotwSet::apply just reported added/updated must be present");
            let endpoints = (*entry.ir).clone();
            if let Err(err) = sink(name.clone(), endpoints).await {
                failed.push((name.clone(), err));
            }
        }

        if !failed.is_empty() {
            let names: BTreeSet<String> = failed.iter().map(|(name, _)| name.clone()).collect();
            self.endpoints.forget(&names);
            let detail = failed
                .into_iter()
                .map(|(name, err)| format!("{name}: {err}"))
                .collect::<Vec<_>>()
                .join("; ");
            return Verdict::Reject(format!("EDS endpoint sink rejected: {detail}"));
        }

        Verdict::Accept
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

    /// EDS is the only type this applier derives a name set for -- CDS/LDS
    /// are wildcard subscriptions (see `subscription.rs`'s own doc on why
    /// `set_names` panics for those), and RDS is not applied here at all.
    /// `client.rs`'s pump calls this after every response, for every state it
    /// holds; returning `None` for anything but EDS is what makes those calls
    /// no-ops.
    fn desired_names(&self, type_url: &str) -> Option<BTreeSet<String>> {
        if type_url == EDS_TYPE_URL {
            Some(self.eds_resource_names())
        } else {
            None
        }
    }
}
