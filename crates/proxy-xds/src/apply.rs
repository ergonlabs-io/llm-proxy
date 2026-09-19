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
//! 6. **RDS is applied per name, with listener warming.** An LDS listener
//!    that names RDS is staged until every named route arrives; a same-name
//!    replacement waiting on a new table retains its last-good listener.
//!    **EDS is applied, as of WP-21 increment 2b-ii, and SDS is applied, as
//!    of WP-22 increment 1.** EDS and SDS have dedicated sinks because their
//!    data is not a listener dependency: `EndpointIR` is already a plain
//!    `Vec`, and [`DynamicSecret`] (in `secret.rs`) is resolved by the SDS
//!    registry. **SDS names its subscription as of WP-22 increment 2a**:
//!    [`ResourceApplier::sds_resource_names`] reads every listener's
//!    `DownstreamTlsSpec::certificate_sds_names`, so `desired_names` answers
//!    a real set for SDS the same way it does for EDS. **What increment 2a
//!    still leaves undone**: an accepted secret reaches the injected
//!    [`PublishSecrets`] sink and stops there -- nothing maps a secret name
//!    back to the `DownstreamTlsFactory` serving that chain, so the proxy
//!    subscribes and ACKs but does not yet serve what arrives. That registry
//!    is increment 2b's, and until it lands an SDS-named chain binds with an
//!    empty cert set and fails every handshake, loudly (see
//!    `DownstreamTlsFactory::build`).
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
use proxy_api::envoy::config::route::v3::RouteConfiguration as RouteConfigurationProto;
use proxy_api::envoy::extensions::transport_sockets::tls::v3::Secret as SecretProto;
use proxy_api::envoy::service::discovery::v3::{
    DeltaDiscoveryResponse, DiscoveryResponse, Resource as DeltaResource,
};
use proxy_config::ir::{
    ClusterConfig, ConfigSnapshot, DynamicSecret, EndpointIR, ListenerConfig, RouteTable,
    SnapshotVersion,
};
use proxy_config::{
    lower_dynamic_cluster, lower_dynamic_endpoints, lower_dynamic_listener, lower_dynamic_route,
};

use crate::client::ResponseHandler;
use crate::delta_client::DeltaResponseHandler;
use crate::secret::decode_secret;
use crate::store::{ApplyError, ApplyOutcome, DeltaApplyError, SetSemantics, SotwSet};
use crate::subscription::Verdict;

/// Full `type_url` a CDS `DiscoveryResponse` carries -- matches the constant
/// `testing/controlplane`'s own selftest uses (`CLUSTER_TYPE_URL`).
const CDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
/// Full `type_url` an LDS `DiscoveryResponse` carries.
const LDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.listener.v3.Listener";
/// Full `type_url` an RDS `DiscoveryResponse` carries.
const RDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.route.v3.RouteConfiguration";
/// EDS's `type_url` -- same reasoning as [`RDS_TYPE_URL`].
const EDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment";
/// Full `type_url` an SDS `DiscoveryResponse` carries -- verified against
/// `secret.proto`'s own `package envoy.extensions.transport_sockets.tls.v3;`
/// plus its `message Secret`, not just copied from memory.
const SDS_TYPE_URL: &str = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret";

fn validate_delta_resource(
    resource: &DeltaResource,
    index: usize,
    response_type_url: &str,
) -> Result<(), String> {
    let path = format!("delta_response.resources[{index}]");
    if resource.name.is_empty() {
        return Err(format!("{path}.name must not be empty"));
    }
    if resource.resource_name.is_some() {
        return Err(format!("{path}.resource_name is not implemented"));
    }
    if !resource.aliases.is_empty() {
        return Err(format!("{path}.aliases is not implemented"));
    }
    if resource.ttl.is_some() {
        return Err(format!("{path}.ttl is not implemented"));
    }
    if resource.cache_control.is_some() {
        return Err(format!("{path}.cache_control is not implemented"));
    }
    let Some(any) = resource.resource.as_ref() else {
        return Err(format!(
            "{path}.resource must be set; delta heartbeat resources are not implemented"
        ));
    };
    if any.type_url != response_type_url {
        return Err(format!(
            "{path}.resource.type_url `{}` does not match delta_response.type_url `{response_type_url}`",
            any.type_url
        ));
    }
    Ok(())
}

fn delta_any(resource: &DeltaResource) -> &prost_types::Any {
    resource
        .resource
        .as_ref()
        .expect("validate_delta_resource checked resource presence")
}

fn delta_apply_error(type_name: &str, error: DeltaApplyError) -> String {
    match error {
        DeltaApplyError::DuplicateName(name) => {
            format!("{type_name} delta response supplied resource `{name}` more than once")
        }
        DeltaApplyError::DuplicateRemoval(name) => {
            format!("{type_name} delta response removed resource `{name}` more than once")
        }
        DeltaApplyError::ConflictingName(name) => {
            format!("{type_name} delta response both supplied and removed resource `{name}`")
        }
    }
}

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
/// The first parameter is a **cluster name** (`Cluster.name`, what
/// `ClusterManager::accept_eds_update` is keyed by) -- NOT the EDS resource
/// name the `ClusterLoadAssignment` arrived under. Envoy allows those to
/// differ (`EdsClusterConfig.service_name` names the resource; a cluster may
/// even leave it unset and subscribe under its own name) and allows several
/// clusters to share one EDS resource, so `on_eds_response` resolves resource
/// name to cluster name(s) itself before ever calling this sink -- see its
/// own doc.
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

/// Where a newly assembled SDS resource's decoded secret goes once it lowers
/// cleanly -- WP-22 increment 1's counterpart to [`PublishEndpoints`], same
/// shape and same reasoning (an injected callback, not a dependency on the
/// real sink; the real one is the WP-08 `ArcSwap` cert resolver, wired in
/// increment 2, and this crate must stay free of that edge).
///
/// One accepted SDS change for the live TLS sink. Delta removals are explicit
/// events so sinks can evict cached payloads and return consumers to their
/// fail-closed pending state.
pub enum SecretUpdate {
    Upsert {
        name: String,
        secret: Arc<DynamicSecret>,
    },
    Remove {
        name: String,
    },
}

pub type PublishSecrets =
    Box<dyn FnMut(SecretUpdate) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>> + Send>;

/// Initialization state after one accepted xDS response has finished all
/// apply, publish, and resource-sink work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitializationEvent {
    /// Type URL of response whose successful application produced this event.
    pub accepted_type_url: String,
    /// Bootstrap configured CDS as a required wildcard ADS source.
    pub cds_required: bool,
    /// Bootstrap configured LDS as a required wildcard ADS source.
    pub lds_required: bool,
    /// EDS resource names required by current cluster configuration.
    pub required_eds: BTreeSet<String>,
    /// EDS resource names currently retained under per-name semantics.
    pub received_eds: BTreeSet<String>,
    /// RDS resource names required by current staged listener configuration.
    pub required_rds: BTreeSet<String>,
    /// RDS resource names currently retained under per-name semantics.
    pub received_rds: BTreeSet<String>,
}

/// Observer for accepted-response initialization state. Output is infallible:
/// initialization bookkeeping must not turn an applied response into a NACK.
pub type InitializationSink =
    Box<dyn FnMut(InitializationEvent) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>;

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

/// Snapshot version is publication bookkeeping, not configuration. Compare
/// only worker-visible resource identities so staging an LDS listener that is
/// still missing RDS does not wake workers or replace last-good handlers.
fn same_published_resources(left: &ConfigSnapshot, right: &ConfigSnapshot) -> bool {
    fn same_map<T>(
        left: &std::collections::HashMap<String, Arc<T>>,
        right: &std::collections::HashMap<String, Arc<T>>,
    ) -> bool {
        left.len() == right.len()
            && left.iter().all(|(name, value)| {
                right
                    .get(name)
                    .is_some_and(|other| Arc::ptr_eq(value, other))
            })
    }

    same_map(&left.listeners, &right.listeners)
        && same_map(&left.clusters, &right.clusters)
        && same_map(&left.routes, &right.routes)
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

/// Same error-root convention as CDS/LDS, for RDS resources.
fn rds_path(any: &prost_types::Any, index: usize) -> String {
    match RouteConfigurationProto::decode(any.value.as_slice()) {
        Ok(route) if !route.name.is_empty() => format!("rds.routes[{}]", route.name),
        _ => format!("rds.routes[{index}]"),
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

/// Same idea as [`cds_path`], for SDS -- `Secret.name` is the resource's own
/// name field (what an `SdsSecretConfig.name` subscribes to).
fn sds_path(any: &prost_types::Any, index: usize) -> String {
    match SecretProto::decode(any.value.as_slice()) {
        Ok(s) if !s.name.is_empty() => format!("sds.secrets[{}]", s.name),
        _ => format!("sds.secrets[{index}]"),
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
    /// RDS resources are per-name: a response omitting an unrelated route
    /// must not un-warm its listener (S8).
    routes: SotwSet<Entry<RouteTable>>,
    /// Last-good dynamic listeners exposed to workers. This differs from
    /// `listeners`, which holds the latest LDS desired set: a replacement
    /// waiting on RDS must not replace a live listener with an unrouteable one.
    active_dynamic_listeners: std::collections::HashMap<String, Arc<ListenerConfig>>,
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
    /// SDS's own set -- `PerName`, like `endpoints` above and for the same
    /// reason: an SDS response only ever carries the secrets a control plane
    /// feels like (re)declaring right now, not every secret ever
    /// subscribed to, so absence must not read as removal (S8: "SDS ... like
    /// EDS ... absence != removal" -- this increment's own brief draws the
    /// parallel explicitly).
    ///
    /// Its static-name set is deliberately EMPTY too, for a parallel reason
    /// to `endpoints`'s: a `Secret.name` and a bootstrap
    /// `static_resources.secrets` entry's name share one proto-level
    /// namespace, but which one actually governs a given listener is decided
    /// by whether that listener's `SdsSecretConfig` sets `sds_config` at all
    /// (unset -> static; set -> SDS) -- not by first-come-first-served over
    /// the name itself, the way CDS/LDS static/dynamic shadowing works. That
    /// decision is `ir.rs`'s to encode once listener wiring lands
    /// (increment 2); seeding a shadow set here now would just be a guess.
    secrets: SotwSet<Entry<DynamicSecret>>,
    /// The snapshot most recently published -- `base` itself until the first
    /// response that actually changes something.
    current: Arc<ConfigSnapshot>,
    publish: Publish,
    /// Where accepted EDS endpoints go. `None` until
    /// [`ResourceApplier::with_endpoint_sink`] wires one -- until then, an
    /// EDS response is refused (see `on_eds_response`).
    endpoint_sink: Option<PublishEndpoints>,
    /// Where accepted SDS secrets go. `None` until
    /// [`ResourceApplier::with_secret_sink`] wires one -- until then, an SDS
    /// response is refused (see `on_sds_response`).
    secret_sink: Option<PublishSecrets>,
    /// Optional startup initialization observer. Existing callers need no
    /// observer and retain identical behavior.
    initialization_sink: Option<InitializationSink>,
}

impl ResourceApplier {
    /// `base` is the static bootstrap snapshot. Its listener and cluster
    /// names become the immune static name sets (`store.rs` rule 3).
    pub fn new(base: Arc<ConfigSnapshot>, publish: Publish) -> Self {
        let static_clusters = base.clusters.keys().cloned().collect();
        let static_listeners = base.listeners.keys().cloned().collect();
        let static_routes = base.routes.keys().cloned().collect();
        Self {
            clusters: SotwSet::new(SetSemantics::FullState, static_clusters),
            listeners: SotwSet::new(SetSemantics::FullState, static_listeners),
            routes: SotwSet::new(SetSemantics::PerName, static_routes),
            active_dynamic_listeners: std::collections::HashMap::new(),
            // Empty static-name set on purpose -- see the field's own doc.
            endpoints: SotwSet::new(SetSemantics::PerName, BTreeSet::new()),
            // Empty static-name set on purpose -- see the field's own doc.
            secrets: SotwSet::new(SetSemantics::PerName, BTreeSet::new()),
            current: Arc::clone(&base),
            base,
            publish,
            endpoint_sink: None,
            secret_sink: None,
            initialization_sink: None,
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

    /// Wire the sink accepted SDS secrets are handed to. Same consuming-
    /// builder shape as [`ResourceApplier::with_endpoint_sink`] and the same
    /// reason: without this, `on_sds_response` keeps refusing SDS by name.
    pub fn with_secret_sink(mut self, sink: PublishSecrets) -> Self {
        self.secret_sink = Some(sink);
        self
    }

    /// Observe initialization state after each accepted SotW or delta
    /// response has completed its apply work.
    pub fn with_initialization_sink(mut self, sink: InitializationSink) -> Self {
        self.initialization_sink = Some(sink);
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

    /// Every secret name a listener in the current snapshot subscribes to,
    /// across both `filter_chains` and `default_filter_chain` (WP-22
    /// increment 2a). A `BTreeSet` both deduplicates -- two chains, or two
    /// listeners, may name the same secret -- and orders, which is what the
    /// subscription's name set wants.
    ///
    /// Only chains whose `SdsSecretConfig` carried an ADS `sds_config` reach
    /// here: lowering refuses the name-only form (it would mean
    /// `static_resources.secrets`, still a stub), so a non-empty
    /// `certificate_sds_names` is always a real ADS subscription.
    pub fn sds_resource_names(&self) -> BTreeSet<String> {
        self.current
            .listeners
            .values()
            .flat_map(|listener| {
                listener
                    .filter_chains
                    .iter()
                    .chain(listener.default_filter_chain.as_ref())
            })
            .filter_map(|chain| chain.transport_socket.as_ref())
            .flat_map(|tls| {
                tls.certificate_sds_names
                    .iter()
                    .cloned()
                    .chain(tls.validation_sds_name.iter().cloned())
            })
            .collect()
    }

    /// RDS names come from the latest LDS set, not `current`: a listener
    /// waiting for its first route table is intentionally absent from the
    /// worker snapshot, but it must still cause the ADS subscription to be
    /// sent. Bootstrap listeners participate too.
    pub fn rds_resource_names(&self) -> BTreeSet<String> {
        self.base
            .listeners
            .values()
            .chain(self.listeners.names().into_iter().map(|name| {
                &self
                    .listeners
                    .get(name)
                    .expect("a listener SotwSet name must resolve to an entry")
                    .ir
            }))
            .flat_map(|listener| listener.rds_route_config_names().cloned())
            .collect()
    }

    /// Decode, validate, apply and publish one response. `Accept` iff every
    /// resource in it lowered cleanly.
    ///
    /// Routing is by the response's own `type_url`. CDS/LDS and RDS publish
    /// only warmed listeners; EDS/SDS use their dedicated sinks.
    ///
    /// `async` since increment 4d-i: publishing (below, via [`Publish`]) can
    /// now await, and this is the method that awaits it, so
    /// [`AdsClient::run_once`](crate::client::AdsClient::run_once) can finish
    /// applying a response before it sends that response's ACK.
    pub async fn on_response(&mut self, resp: &DiscoveryResponse) -> Verdict {
        let verdict = match resp.type_url.as_str() {
            CDS_TYPE_URL => self.on_cds_response(resp).await,
            LDS_TYPE_URL => self.on_lds_response(resp).await,
            EDS_TYPE_URL => self.on_eds_response(resp).await,
            SDS_TYPE_URL => self.on_sds_response(resp).await,
            RDS_TYPE_URL => self.on_rds_response(resp).await,
            other => Verdict::Reject(format!("unknown ADS type_url `{other}`")),
        };
        if verdict == Verdict::Accept {
            self.emit_initialization_event(&resp.type_url).await;
        }
        verdict
    }

    /// Validate, apply, then ACK/NACK one delta response. Wrapper fields not
    /// represented by current IR are refused by dotted path rather than
    /// silently ignored.
    pub async fn on_delta_response(&mut self, response: &DeltaDiscoveryResponse) -> Verdict {
        if !response.removed_resource_names.is_empty() {
            return Verdict::Reject(
                "delta_response.removed_resource_names is not implemented; use removed_resources"
                    .to_string(),
            );
        }
        if !response.resource_errors.is_empty() {
            return Verdict::Reject(
                "delta_response.resource_errors is not implemented".to_string(),
            );
        }
        for (index, resource) in response.resources.iter().enumerate() {
            if let Err(error) = validate_delta_resource(resource, index, &response.type_url) {
                return Verdict::Reject(error);
            }
        }

        let verdict = match response.type_url.as_str() {
            CDS_TYPE_URL => self.on_delta_cds_response(response).await,
            LDS_TYPE_URL => self.on_delta_lds_response(response).await,
            RDS_TYPE_URL => self.on_delta_rds_response(response).await,
            EDS_TYPE_URL => self.on_delta_eds_response(response).await,
            SDS_TYPE_URL => self.on_delta_sds_response(response).await,
            other => Verdict::Reject(format!("unknown delta ADS type_url `{other}`")),
        };
        if verdict == Verdict::Accept {
            self.emit_initialization_event(&response.type_url).await;
        }
        verdict
    }

    async fn emit_initialization_event(&mut self, accepted_type_url: &str) {
        if self.initialization_sink.is_none() {
            return;
        }
        let (cds_required, lds_required) = self
            .base
            .ads
            .as_ref()
            .map(|ads| (ads.cds, ads.lds))
            .unwrap_or((false, false));
        let event = InitializationEvent {
            accepted_type_url: accepted_type_url.to_string(),
            cds_required,
            lds_required,
            required_eds: self.eds_resource_names(),
            received_eds: self
                .endpoints
                .names()
                .into_iter()
                .map(str::to_string)
                .collect(),
            required_rds: self.rds_resource_names(),
            received_rds: self
                .routes
                .names()
                .into_iter()
                .map(str::to_string)
                .collect(),
        };
        self.initialization_sink
            .as_mut()
            .expect("initialization sink presence checked above")(event)
        .await;
    }

    async fn on_delta_cds_response(&mut self, response: &DeltaDiscoveryResponse) -> Verdict {
        let mut pairs = Vec::with_capacity(response.resources.len());
        for (index, resource) in response.resources.iter().enumerate() {
            let any = delta_any(resource);
            let path = format!("delta_response.resources[{index}].resource");
            let ir = match lower_dynamic_cluster(any, &path) {
                Ok(ir) => ir,
                Err(error) => return Verdict::Reject(error.to_string()),
            };
            if ir.name != resource.name {
                return Verdict::Reject(format!(
                    "delta_response.resources[{index}].name `{}` does not match resource name `{}`",
                    resource.name, ir.name
                ));
            }
            pairs.push((
                resource.name.clone(),
                Entry {
                    raw: any.value.clone(),
                    ir: Arc::new(ir),
                },
            ));
        }
        let outcome = match self
            .clusters
            .apply_delta(pairs, &response.removed_resources)
        {
            Ok(outcome) => outcome,
            Err(error) => return Verdict::Reject(delta_apply_error("CDS", error)),
        };
        self.finish(outcome, "cluster").await
    }

    async fn on_delta_lds_response(&mut self, response: &DeltaDiscoveryResponse) -> Verdict {
        let mut pairs = Vec::with_capacity(response.resources.len());
        for (index, resource) in response.resources.iter().enumerate() {
            let any = delta_any(resource);
            let path = format!("delta_response.resources[{index}].resource");
            let ir = match lower_dynamic_listener(any, &path) {
                Ok(ir) => ir,
                Err(error) => return Verdict::Reject(error.to_string()),
            };
            if ir.name != resource.name {
                return Verdict::Reject(format!(
                    "delta_response.resources[{index}].name `{}` does not match resource name `{}`",
                    resource.name, ir.name
                ));
            }
            pairs.push((
                resource.name.clone(),
                Entry {
                    raw: any.value.clone(),
                    ir: Arc::new(ir),
                },
            ));
        }
        let outcome = match self
            .listeners
            .apply_delta(pairs, &response.removed_resources)
        {
            Ok(outcome) => outcome,
            Err(error) => return Verdict::Reject(delta_apply_error("LDS", error)),
        };
        self.finish(outcome, "listener").await
    }

    async fn on_delta_rds_response(&mut self, response: &DeltaDiscoveryResponse) -> Verdict {
        let mut pairs = Vec::with_capacity(response.resources.len());
        for (index, resource) in response.resources.iter().enumerate() {
            let any = delta_any(resource);
            let path = format!("delta_response.resources[{index}].resource");
            let ir = match lower_dynamic_route(any, &path) {
                Ok(ir) => ir,
                Err(error) => return Verdict::Reject(error.to_string()),
            };
            if ir.name != resource.name {
                return Verdict::Reject(format!(
                    "delta_response.resources[{index}].name `{}` does not match resource name `{}`",
                    resource.name, ir.name
                ));
            }
            pairs.push((
                resource.name.clone(),
                Entry {
                    raw: any.value.clone(),
                    ir: Arc::new(ir),
                },
            ));
        }
        let outcome = match self.routes.apply_delta(pairs, &response.removed_resources) {
            Ok(outcome) => outcome,
            Err(error) => return Verdict::Reject(delta_apply_error("RDS", error)),
        };
        self.finish(outcome, "route configuration").await
    }

    async fn on_delta_eds_response(&mut self, response: &DeltaDiscoveryResponse) -> Verdict {
        if self.endpoint_sink.is_none() {
            return Verdict::Reject(format!(
                "EDS (`{EDS_TYPE_URL}`) is not applied: this ResourceApplier has no endpoint sink wired"
            ));
        }
        let mut pairs = Vec::with_capacity(response.resources.len());
        for (index, resource) in response.resources.iter().enumerate() {
            let any = delta_any(resource);
            let path = format!("delta_response.resources[{index}].resource");
            let (name, endpoints) = match lower_dynamic_endpoints(any, &path) {
                Ok(value) => value,
                Err(error) => return Verdict::Reject(error.to_string()),
            };
            if name != resource.name {
                return Verdict::Reject(format!(
                    "delta_response.resources[{index}].name `{}` does not match resource name `{name}`",
                    resource.name
                ));
            }
            pairs.push((
                name,
                Entry {
                    raw: any.value.clone(),
                    ir: Arc::new(endpoints),
                },
            ));
        }

        let previous = self.endpoints.clone();
        let outcome = match self
            .endpoints
            .apply_delta(pairs, &response.removed_resources)
        {
            Ok(outcome) => outcome,
            Err(error) => return Verdict::Reject(delta_apply_error("EDS", error)),
        };
        let updates: Vec<_> = outcome
            .added
            .iter()
            .chain(outcome.updated.iter())
            .map(|resource_name| {
                let endpoints = self
                    .endpoints
                    .get(resource_name)
                    .expect("delta EDS update must be present")
                    .ir
                    .as_ref()
                    .clone();
                (
                    resource_name.clone(),
                    endpoints,
                    self.eds_clusters_for(resource_name),
                )
            })
            .collect();
        let removals: Vec<_> = outcome
            .removed
            .iter()
            .map(|resource_name| (resource_name.clone(), self.eds_clusters_for(resource_name)))
            .collect();

        let sink = self
            .endpoint_sink
            .as_mut()
            .expect("endpoint sink presence checked above");
        let mut failures = Vec::new();
        for (resource_name, endpoints, cluster_names) in updates {
            for cluster_name in cluster_names {
                if let Err(error) = sink(cluster_name.clone(), endpoints.clone()).await {
                    failures.push(format!(
                        "{cluster_name} (resource `{resource_name}`): {error}"
                    ));
                }
            }
        }
        for (resource_name, cluster_names) in removals {
            for cluster_name in cluster_names {
                if let Err(error) = sink(cluster_name.clone(), Vec::new()).await {
                    failures.push(format!(
                        "{cluster_name} (removed resource `{resource_name}`): {error}"
                    ));
                }
            }
        }
        if failures.is_empty() {
            Verdict::Accept
        } else {
            self.endpoints = previous;
            Verdict::Reject(format!(
                "EDS endpoint sink rejected: {}",
                failures.join("; ")
            ))
        }
    }

    async fn on_delta_sds_response(&mut self, response: &DeltaDiscoveryResponse) -> Verdict {
        let Some(sink) = self.secret_sink.as_mut() else {
            return Verdict::Reject(format!(
                "SDS (`{SDS_TYPE_URL}`) is not applied: this ResourceApplier has no secret sink wired"
            ));
        };
        let mut pairs = Vec::with_capacity(response.resources.len());
        for (index, resource) in response.resources.iter().enumerate() {
            let any = delta_any(resource);
            let path = format!("delta_response.resources[{index}].resource");
            let secret = match decode_secret(any, &path) {
                Ok(secret) => secret,
                Err(error) => return Verdict::Reject(error.to_string()),
            };
            if secret.name != resource.name {
                return Verdict::Reject(format!(
                    "delta_response.resources[{index}].name `{}` does not match resource name `{}`",
                    resource.name, secret.name
                ));
            }
            pairs.push((
                resource.name.clone(),
                Entry {
                    raw: any.value.clone(),
                    ir: Arc::new(secret),
                },
            ));
        }
        let previous = self.secrets.clone();
        let outcome = match self.secrets.apply_delta(pairs, &response.removed_resources) {
            Ok(outcome) => outcome,
            Err(error) => return Verdict::Reject(delta_apply_error("SDS", error)),
        };
        let mut failures = Vec::new();
        for name in outcome.added.iter().chain(outcome.updated.iter()) {
            let secret = Arc::clone(
                &self
                    .secrets
                    .get(name)
                    .expect("delta SDS update must be present")
                    .ir,
            );
            if let Err(error) = sink(SecretUpdate::Upsert {
                name: name.clone(),
                secret,
            })
            .await
            {
                failures.push(format!("{name}: {error}"));
            }
        }
        for name in &response.removed_resources {
            if let Err(error) = sink(SecretUpdate::Remove { name: name.clone() }).await {
                failures.push(format!("{name} (removed): {error}"));
            }
        }
        if failures.is_empty() {
            Verdict::Accept
        } else {
            self.secrets = previous;
            Verdict::Reject(format!("SDS secret sink rejected: {}", failures.join("; ")))
        }
    }

    fn eds_clusters_for(&self, resource_name: &str) -> Vec<String> {
        self.current
            .clusters
            .iter()
            .filter(|(_, cluster)| {
                cluster.eds.as_ref().map(|eds| eds.service_name.as_str()) == Some(resource_name)
            })
            .map(|(name, _)| name.clone())
            .collect()
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

    /// RDS is `PerName`: an omitted route is not a deletion. A changed route
    /// can promote a listener LDS staged earlier, or rebuild a live listener
    /// against a new immutable table, but an RDS update never tears down an
    /// unrelated listener.
    async fn on_rds_response(&mut self, resp: &DiscoveryResponse) -> Verdict {
        let mut pairs = Vec::with_capacity(resp.resources.len());
        for (index, any) in resp.resources.iter().enumerate() {
            let path = rds_path(any, index);
            let ir = match lower_dynamic_route(any, &path) {
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
        let outcome = match self.routes.apply(pairs) {
            Ok(outcome) => outcome,
            Err(ApplyError::DuplicateName(name)) => {
                return Verdict::Reject(format!(
                    "RDS response named route configuration `{name}` more than once"
                ));
            }
        };
        self.finish(outcome, "route configuration").await
    }

    /// EDS has no `finish` call -- unlike CDS/LDS, an accepted endpoint
    /// update never touches `ConfigSnapshot` or `self.publish` (see
    /// `endpoints`'s own doc); it goes straight to the injected
    /// [`PublishEndpoints`] sink instead, once per **cluster** actually fed by
    /// a resource `added` or `updated` (never `unchanged` -- that suppression
    /// is the whole point of `Entry`'s byte comparison).
    ///
    /// A `ClusterLoadAssignment`'s own `cluster_name` field is the EDS
    /// resource name -- what `EdsClusterConfig.service_name` subscribes to --
    /// not necessarily any `Cluster.name`; Envoy allows those to differ and
    /// allows several clusters to share one resource. So this resolves each
    /// resource to every cluster in `self.current` whose `eds.service_name`
    /// names it, and calls the sink once per matching cluster, with that
    /// cluster's OWN name -- never the resource name straight through.
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
        // RESOURCE names for which any fed cluster's sink call failed, so a
        // later retransmission of identical bytes reads as `added` again
        // instead of `unchanged` and reaches the sink a second time. Names
        // that succeeded stay recorded -- there is no reason to make the sink
        // redo work it already did. The store stays keyed by resource name
        // throughout (it is a cache of what arrived on the wire); only the
        // sink call itself is keyed by cluster name.
        let mut failed_resources: BTreeSet<String> = BTreeSet::new();
        let mut failure_detail: Vec<String> = Vec::new();
        for name in outcome.added.iter().chain(outcome.updated.iter()) {
            let entry = self
                .endpoints
                .get(name)
                .expect("a name SotwSet::apply just reported added/updated must be present");
            let endpoints = (*entry.ir).clone();

            // Resolve resource name -> cluster name(s): every cluster in the
            // CURRENT snapshot whose `eds_cluster_config.service_name` names
            // this resource. Not the `Any`'s own name -- see this method's
            // doc.
            let cluster_names: Vec<String> = self
                .current
                .clusters
                .iter()
                .filter(|(_, cluster)| {
                    cluster.eds.as_ref().map(|eds| &eds.service_name) == Some(name)
                })
                .map(|(cluster_name, _)| cluster_name.clone())
                .collect();

            if cluster_names.is_empty() {
                // A control plane pushing a resource nobody subscribed to is
                // ITS bug, not a reason to NACK the whole response and stall
                // every other resource in it that DID match a cluster --
                // same "loud, not a reject" shape as `shadowed_by_static` in
                // `finish` above.
                tracing::warn!(
                    resource = %name,
                    "EDS resource `{name}` matches no cluster's `eds_cluster_config.service_name`; \
                     accepted on the wire but not installed anywhere"
                );
                continue;
            }

            for cluster_name in cluster_names {
                if let Err(err) = sink(cluster_name.clone(), endpoints.clone()).await {
                    failed_resources.insert(name.clone());
                    failure_detail.push(format!("{cluster_name} (resource `{name}`): {err}"));
                }
            }
        }

        if !failed_resources.is_empty() {
            self.endpoints.forget(&failed_resources);
            return Verdict::Reject(format!(
                "EDS endpoint sink rejected: {}",
                failure_detail.join("; ")
            ));
        }

        Verdict::Accept
    }

    /// Like `on_eds_response`, but simpler: an SDS secret is not resolved to
    /// any other name before reaching the sink -- `Secret.name` IS the name
    /// the sink is called under, since (unlike EDS's resource-name-vs-
    /// cluster-name split) there is no other resource in `self.current` for
    /// an SDS name to resolve through in this increment (that correlation --
    /// a listener's `SdsSecretConfig.name` -- is increment 2's, per this
    /// module's SDS scope note). No `finish` call either, for the same
    /// reason `on_eds_response` skips it: an accepted secret never touches
    /// `ConfigSnapshot` or `self.publish`, only the injected sink.
    async fn on_sds_response(&mut self, resp: &DiscoveryResponse) -> Verdict {
        let Some(sink) = self.secret_sink.as_mut() else {
            return Verdict::Reject(format!(
                "SDS (`{SDS_TYPE_URL}`) is not applied: this ResourceApplier has no secret \
                 sink wired -- see `ResourceApplier::with_secret_sink`"
            ));
        };

        let mut pairs = Vec::with_capacity(resp.resources.len());
        for (index, any) in resp.resources.iter().enumerate() {
            let path = sds_path(any, index);
            let secret = match decode_secret(any, &path) {
                Ok(secret) => secret,
                // Rule 1 (all-or-nothing): bail out before touching
                // `self.secrets` at all -- nothing lowered so far is
                // applied, and the sink is never called for this response.
                Err(err) => return Verdict::Reject(err.to_string()),
            };
            let name = secret.name.clone();
            pairs.push((
                name,
                Entry {
                    raw: any.value.clone(),
                    ir: Arc::new(secret),
                },
            ));
        }

        let outcome = match self.secrets.apply(pairs) {
            Ok(outcome) => outcome,
            Err(ApplyError::DuplicateName(name)) => {
                return Verdict::Reject(format!(
                    "SDS response named secret `{name}` more than once"
                ));
            }
        };

        // Same store-consistency fix-up as `on_eds_response`: `apply` above
        // already recorded every added/updated name BEFORE the sink below
        // has run, so a sink failure must `forget` exactly the names it
        // failed for -- otherwise an identical retransmission would compare
        // `unchanged` and never reach the sink again. See `SotwSet::forget`'s
        // own doc.
        let mut failed: BTreeSet<String> = BTreeSet::new();
        let mut failure_detail: Vec<String> = Vec::new();
        for name in outcome.added.iter().chain(outcome.updated.iter()) {
            let entry = self
                .secrets
                .get(name)
                .expect("a name SotwSet::apply just reported added/updated must be present");
            if let Err(err) = sink(SecretUpdate::Upsert {
                name: name.clone(),
                secret: Arc::clone(&entry.ir),
            })
            .await
            {
                failed.insert(name.clone());
                failure_detail.push(format!("{name}: {err}"));
            }
        }

        if !failed.is_empty() {
            self.secrets.forget(&failed);
            return Verdict::Reject(format!(
                "SDS secret sink rejected: {}",
                failure_detail.join("; ")
            ));
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

        self.refresh_active_dynamic_listeners();
        let snapshot = self.assemble_snapshot();
        if !same_published_resources(&self.current, &snapshot) {
            (self.publish)(Arc::clone(&snapshot)).await;
            self.current = snapshot;
        }
        Verdict::Accept
    }

    /// Return all routes known to the staged resource sets. RDS resources are
    /// exposed in the snapshot as well as used for the warm-up check so an
    /// accept loop rebuild sees the exact immutable table that admitted it.
    fn staged_routes(&self) -> std::collections::HashMap<String, Arc<RouteTable>> {
        let mut routes = self.base.routes.clone();
        for name in self.routes.names() {
            let entry = self
                .routes
                .get(name)
                .expect("a route SotwSet name must resolve to an entry");
            routes.insert(name.to_string(), Arc::clone(&entry.ir));
        }
        routes
    }

    /// Promote a complete LDS generation only after every listener in it has
    /// its RDS dependencies. Until then, retain the whole last-good listener
    /// set. An LDS response is SotW, so retaining only a same-named listener
    /// would still withdraw a renamed old listener before its replacement is
    /// warm -- the precise outage make-before-break must avoid.
    ///
    /// An explicitly empty LDS generation remains a deliberate removal and
    /// therefore promotes immediately.
    fn refresh_active_dynamic_listeners(&mut self) {
        let routes = self.staged_routes();
        let mut next = std::collections::HashMap::new();
        for name in self.listeners.names() {
            let listener = self
                .listeners
                .get(name)
                .expect("a listener SotwSet name must resolve to an entry");
            if !listener.ir.routes_are_warmed(&routes) {
                return;
            }
            next.insert(name.to_string(), Arc::clone(&listener.ir));
        }
        self.active_dynamic_listeners = next;
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
        let listeners = self.active_dynamic_listeners.clone();
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
        let routes = self
            .routes
            .names()
            .into_iter()
            .map(|name| {
                let entry = self
                    .routes
                    .get(name)
                    .expect("a route SotwSet name must resolve to an entry");
                (name.to_string(), Arc::clone(&entry.ir))
            })
            .collect();

        Arc::new(self.base.with_dynamic_resources(
            listeners,
            clusters,
            routes,
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

    /// EDS, RDS and SDS are the types this applier derives a name set for --
    /// CDS/LDS are wildcard subscriptions (see `subscription.rs`'s own doc on
    /// why `set_names` panics for those). `client.rs`'s pump calls this after
    /// every response, for every state it holds; returning `None` is what
    /// makes those calls no-ops.
    ///
    /// SDS joined EDS in WP-22 increment 2a, once
    /// `DownstreamTlsSpec::certificate_sds_names` gave the snapshot somewhere
    /// to read the names from.
    fn desired_names(&self, type_url: &str) -> Option<BTreeSet<String>> {
        match type_url {
            EDS_TYPE_URL => Some(self.eds_resource_names()),
            RDS_TYPE_URL => Some(self.rds_resource_names()),
            SDS_TYPE_URL => Some(self.sds_resource_names()),
            _ => None,
        }
    }
}

impl DeltaResponseHandler for ResourceApplier {
    fn handle(
        &mut self,
        response: &DeltaDiscoveryResponse,
    ) -> impl Future<Output = Verdict> + Send {
        self.on_delta_response(response)
    }

    fn desired_names(&self, type_url: &str) -> Option<BTreeSet<String>> {
        <Self as ResponseHandler>::desired_names(self, type_url)
    }
}

/// WP-22 increment 1 acceptance tests for `on_sds_response`, colocated here
/// (rather than in `tests/apply.rs`, which this increment does not own) --
/// same idiom `store.rs` already uses for its own `SotwSet` tests. Fixture
/// shape mirrors `tests/apply.rs`'s EDS fixtures as closely as a single-file
/// test module can: hand-build the proto, wrap it via `any_of`, drive
/// `ResourceApplier::on_response` directly.
#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Mutex;

    use proxy_api::envoy::config::core::v3::data_source::Specifier;
    use proxy_api::envoy::config::core::v3::DataSource;
    use proxy_api::envoy::extensions::transport_sockets::tls::v3::secret::Type as SecretOneof;
    use proxy_api::envoy::extensions::transport_sockets::tls::v3::{
        CertificateValidationContext, TlsCertificate,
    };
    use proxy_config::ir::ConfigSnapshot;

    use super::*;
    use proxy_config::ir::SecretKind;

    const SECRET_TYPE: &str = "envoy.extensions.transport_sockets.tls.v3.Secret";

    fn any_of<T: Message>(msg: &T, type_name: &str) -> prost_types::Any {
        prost_types::Any {
            type_url: format!("type.googleapis.com/{type_name}"),
            value: msg.encode_to_vec(),
        }
    }

    fn inline_bytes(bytes: &[u8]) -> DataSource {
        DataSource {
            specifier: Some(Specifier::InlineBytes(bytes.to_vec())),
            ..Default::default()
        }
    }

    fn tls_cert_secret(name: &str, chain: &[u8], key: &[u8]) -> SecretProto {
        SecretProto {
            name: name.to_string(),
            r#type: Some(SecretOneof::TlsCertificate(TlsCertificate {
                certificate_chain: Some(inline_bytes(chain)),
                private_key: Some(inline_bytes(key)),
                ..Default::default()
            })),
        }
    }

    fn validation_context_secret(name: &str, trusted_ca: &[u8]) -> SecretProto {
        SecretProto {
            name: name.to_string(),
            r#type: Some(SecretOneof::ValidationContext(
                CertificateValidationContext {
                    trusted_ca: Some(inline_bytes(trusted_ca)),
                    ..Default::default()
                },
            )),
        }
    }

    fn sds_response(version: &str, secrets: &[SecretProto]) -> DiscoveryResponse {
        DiscoveryResponse {
            version_info: version.to_string(),
            type_url: SDS_TYPE_URL.to_string(),
            nonce: format!("n-{version}"),
            resources: secrets.iter().map(|s| any_of(s, SECRET_TYPE)).collect(),
            ..Default::default()
        }
    }

    fn empty_base() -> Arc<ConfigSnapshot> {
        Arc::new(ConfigSnapshot::default())
    }

    fn recording_publisher() -> (Publish, Arc<Mutex<Vec<Arc<ConfigSnapshot>>>>) {
        let published: Arc<Mutex<Vec<Arc<ConfigSnapshot>>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&published);
        let publish: Publish = Box::new(move |snapshot| {
            recorded.lock().unwrap().push(snapshot);
            Box::pin(std::future::ready(()))
        });
        (publish, published)
    }

    /// What [`recording_secret_sink`] hands back: every successful sink call,
    /// in order, as `(name, secret)`.
    type RecordedSecretCalls = Arc<Mutex<Vec<(String, Arc<DynamicSecret>)>>>;
    type RecordedSecretRemovals = Arc<Mutex<Vec<String>>>;

    /// A recording [`PublishSecrets`]: same shape as `tests/apply.rs`'s own
    /// `recording_endpoint_sink` -- `fail_names` lists secret names whose
    /// FIRST call must return `Err`, consumed on that first failure so a
    /// later retry for the same name succeeds.
    fn recording_secret_sink(
        fail_names: &[&str],
    ) -> (PublishSecrets, RecordedSecretCalls, RecordedSecretRemovals) {
        let recorded: RecordedSecretCalls = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::clone(&recorded);
        let removals: RecordedSecretRemovals = Arc::new(Mutex::new(Vec::new()));
        let recorded_removals = Arc::clone(&removals);
        let mut still_failing: HashSet<String> = fail_names.iter().map(|s| s.to_string()).collect();
        let sink: PublishSecrets = Box::new(move |update| {
            let name = match &update {
                SecretUpdate::Upsert { name, .. } | SecretUpdate::Remove { name } => name,
            };
            if still_failing.remove(name) {
                return Box::pin(std::future::ready(Err(format!(
                    "sink deliberately failed for `{name}`"
                ))));
            }
            match update {
                SecretUpdate::Upsert { name, secret } => {
                    calls.lock().unwrap().push((name, secret));
                }
                SecretUpdate::Remove { name } => {
                    recorded_removals.lock().unwrap().push(name);
                }
            }
            Box::pin(std::future::ready(Ok(())))
        });
        (sink, recorded, removals)
    }

    #[tokio::test]
    async fn a_well_formed_inline_tls_certificate_secret_reaches_the_sink() {
        let (publish, _published) = recording_publisher();
        let (sink, recorded, _removals) = recording_secret_sink(&[]);
        let mut applier = ResourceApplier::new(empty_base(), publish).with_secret_sink(sink);

        let resp = sds_response("v1", &[tls_cert_secret("cert-1", b"chain", b"key")]);
        let verdict = applier.on_response(&resp).await;

        assert_eq!(verdict, Verdict::Accept);
        let calls = recorded.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "cert-1");
        match &calls[0].1.kind {
            SecretKind::TlsCertificate {
                certificate_chain,
                private_key,
            } => {
                assert_eq!(certificate_chain, b"chain");
                assert_eq!(private_key, b"key");
            }
            SecretKind::ValidationContext { .. } => panic!("expected TlsCertificate"),
        }
    }

    #[tokio::test]
    async fn a_well_formed_validation_context_secret_lowers_and_reaches_the_sink() {
        let (publish, _published) = recording_publisher();
        let (sink, recorded, _removals) = recording_secret_sink(&[]);
        let mut applier = ResourceApplier::new(empty_base(), publish).with_secret_sink(sink);

        let resp = sds_response("v1", &[validation_context_secret("ca-1", b"ca-bytes")]);
        let verdict = applier.on_response(&resp).await;

        assert_eq!(verdict, Verdict::Accept);
        let calls = recorded.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "ca-1");
        match &calls[0].1.kind {
            SecretKind::ValidationContext { trusted_ca } => {
                assert_eq!(trusted_ca, b"ca-bytes");
            }
            SecretKind::TlsCertificate { .. } => panic!("expected ValidationContext"),
        }
    }

    /// PerName semantics (S8: SDS absence != removal), proven the same way
    /// `store.rs`'s own `SotwSet` tests prove it: a THIRD response resending
    /// `cert-a`'s identical bytes must still compare `unchanged` and NOT
    /// reach the sink again, even though the middle response never mentioned
    /// `cert-a` at all. If the second response had (wrongly) treated the
    /// omission as a removal, this third response would read as `added`
    /// again and call the sink a second time.
    #[tokio::test]
    async fn a_second_response_omitting_a_previously_seen_secret_does_not_remove_it() {
        let (publish, _published) = recording_publisher();
        let (sink, recorded, _removals) = recording_secret_sink(&[]);
        let mut applier = ResourceApplier::new(empty_base(), publish).with_secret_sink(sink);

        let resp_a = sds_response("v1", &[tls_cert_secret("cert-a", b"chain-a", b"key-a")]);
        let verdict = applier.on_response(&resp_a).await;
        assert_eq!(verdict, Verdict::Accept);
        assert_eq!(recorded.lock().unwrap().len(), 1);

        // Second response carries only `cert-b` -- `cert-a` is absent, not
        // resent.
        let resp_b = sds_response("v2", &[tls_cert_secret("cert-b", b"chain-b", b"key-b")]);
        let verdict = applier.on_response(&resp_b).await;
        assert_eq!(verdict, Verdict::Accept);
        assert_eq!(recorded.lock().unwrap().len(), 2);

        // Third response resends `cert-a`'s EXACT bytes. Under PerName, the
        // store never forgot it, so this compares `unchanged` and the sink is
        // not called again.
        let verdict = applier.on_response(&resp_a).await;
        assert_eq!(verdict, Verdict::Accept);
        assert_eq!(
            recorded.lock().unwrap().len(),
            2,
            "cert-a was never removed by its absence from the middle response, so resending its \
             identical bytes must compare unchanged, not added"
        );
    }

    /// The store-consistency fix-up on `on_sds_response`, same deliverable as
    /// `tests/apply.rs`'s own
    /// `a_sink_that_fails_once_is_retried_on_the_next_identical_response` for
    /// EDS: `apply` records a name as added/updated before the sink runs, so
    /// a sink failure must `forget` it -- otherwise a later identical
    /// retransmission would compare `unchanged` and the secret would stay
    /// permanently unpublished while the store reports it fine.
    #[tokio::test]
    async fn a_sink_failure_leaves_the_set_as_if_the_secret_never_arrived() {
        let (publish, _published) = recording_publisher();
        let (sink, recorded, _removals) = recording_secret_sink(&["cert-1"]);
        let mut applier = ResourceApplier::new(empty_base(), publish).with_secret_sink(sink);

        let resp = sds_response("v1", &[tls_cert_secret("cert-1", b"chain", b"key")]);

        let first = applier.on_response(&resp).await;
        assert!(
            matches!(first, Verdict::Reject(_)),
            "expected the first attempt to reject (sink fails), got {first:?}"
        );
        assert!(recorded.lock().unwrap().is_empty());

        // Same bytes again. If the store were left believing the first
        // attempt applied, this would come back `unchanged` and the sink
        // would never be asked again.
        let second = applier.on_response(&resp).await;
        assert_eq!(
            second,
            Verdict::Accept,
            "the retry must reach the sink, which now succeeds"
        );
        let calls = recorded.lock().unwrap();
        assert_eq!(calls.len(), 1, "the sink must be called on the retry");
        assert_eq!(calls[0].0, "cert-1");
    }

    #[tokio::test]
    async fn an_sds_response_with_no_sink_wired_is_rejected_naming_the_reason() {
        let (publish, _published) = recording_publisher();
        let mut applier = ResourceApplier::new(empty_base(), publish);

        let resp = sds_response("v1", &[tls_cert_secret("cert-1", b"chain", b"key")]);
        let verdict = applier.on_response(&resp).await;
        let Verdict::Reject(message) = verdict else {
            panic!("expected Reject, got {verdict:?}");
        };
        assert!(
            message.contains("no secret sink"),
            "message should say why, got: {message}"
        );
    }

    #[tokio::test]
    async fn an_sds_response_naming_a_secret_twice_is_rejected() {
        let (publish, _published) = recording_publisher();
        let (sink, recorded, _removals) = recording_secret_sink(&[]);
        let mut applier = ResourceApplier::new(empty_base(), publish).with_secret_sink(sink);

        let resp = sds_response(
            "v1",
            &[
                tls_cert_secret("dup", b"chain-1", b"key-1"),
                tls_cert_secret("dup", b"chain-2", b"key-2"),
            ],
        );
        let verdict = applier.on_response(&resp).await;
        assert!(
            matches!(verdict, Verdict::Reject(_)),
            "expected Reject, got {verdict:?}"
        );
        assert!(recorded.lock().unwrap().is_empty());
    }

    /// A `filename` `DataSource` is refused with its full dotted path --
    /// response-level parity with `secret.rs`'s own decode-level test, since
    /// the acceptance list asks for both.
    #[tokio::test]
    async fn an_sds_response_with_a_filename_data_source_is_rejected_with_its_full_dotted_path() {
        let (publish, _published) = recording_publisher();
        let (sink, recorded, _removals) = recording_secret_sink(&[]);
        let mut applier = ResourceApplier::new(empty_base(), publish).with_secret_sink(sink);

        let bad = SecretProto {
            name: "cert-1".to_string(),
            r#type: Some(SecretOneof::TlsCertificate(TlsCertificate {
                certificate_chain: Some(DataSource {
                    specifier: Some(Specifier::Filename("/etc/certs/chain.pem".to_string())),
                    ..Default::default()
                }),
                private_key: Some(inline_bytes(b"key")),
                ..Default::default()
            })),
        };
        let resp = sds_response("v1", &[bad]);
        let verdict = applier.on_response(&resp).await;
        let Verdict::Reject(message) = verdict else {
            panic!("expected Reject, got {verdict:?}");
        };
        assert!(
            message.contains("sds.secrets[cert-1].tls_certificate.certificate_chain.filename"),
            "message should carry the full dotted path, got: {message}"
        );
        assert!(recorded.lock().unwrap().is_empty());
    }
}
