//! Turning an ACCEPTED `DiscoveryResponse` into a published [`ConfigSnapshot`]
//! (S8). `store.rs` stays free of protobuf and `proxy-config`; this module
//! does the lowering.
//!
//! Responses are validated, then applied all-or-nothing:
//!
//! 1. Every resource is lowered to IR before any touches a [`SotwSet`]. One
//!    failure discards the whole response: no partial apply, no publish, and
//!    [`ResourceApplier::current`] does not move.
//! 2. `Any` carries no name, so a resource is decoded twice on the happy path:
//!    once best-effort to label error paths, then for real by the `lower_*`
//!    functions, whose IR carries `.name`.
//! 3. The `unchanged`/`updated` decision compares raw bytes, not IR (see
//!    [`Entry`]).
//! 4. A response that changes nothing publishes nothing. It is still `Accept`ed.
//! 5. A dynamic name shadowed by a static resource warns and keeps the static
//!    definition serving (`internal-docs/envoy-divergences.md`).
//! 6. RDS is applied per name, with listener warming: an LDS listener naming
//!    RDS stays staged until its routes arrive. EDS and SDS have dedicated
//!    sinks because they are not listener dependencies. Endpoints go to the
//!    cluster manager; secrets go to [`PublishSecrets`].
//!
//! EDS and SDS sets are `PerName` (absence is not removal) and seeded with an
//! empty static-name set. A static cluster fed dynamically is the case EDS
//! exists for, so its names must not be shadowed. A sink failure NACKs and
//! calls [`SotwSet::forget`] so an identical retransmission is not stuck as
//! `unchanged`. An EDS or SDS response with no sink wired is a NACK, not a
//! silent accept.
//!
//! Ordering across types (S8: `CDS -> EDS -> LDS -> RDS`) is `SotwSet`'s job
//! (`store.rs`). This module keeps one independent [`SotwSet`] per type.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
/// Full `type_url` an SDS `DiscoveryResponse` carries. A wrong value is a
/// subscription the control plane never answers and never reports, so it must
/// match `secret.proto` exactly.
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
    if resource.aliases.iter().any(String::is_empty) {
        return Err(format!("{path}.aliases must not contain empty names"));
    }
    if resource.cache_control.is_some() {
        return Err(format!("{path}.cache_control is not implemented"));
    }
    if let Some(ttl) = resource.ttl.as_ref() {
        if ttl.seconds < 0 || ttl.nanos < 0 || ttl.nanos >= 1_000_000_000 {
            return Err(format!("{path}.ttl must be a positive finite duration"));
        }
        if ttl.seconds == 0 && ttl.nanos == 0 {
            return Err(format!("{path}.ttl must be a positive finite duration"));
        }
    }
    if let Some(any) = resource.resource.as_ref() {
        if any.type_url != response_type_url {
            return Err(format!(
                "{path}.resource.type_url `{}` does not match delta_response.type_url `{response_type_url}`",
                any.type_url
            ));
        }
    }
    Ok(())
}

fn delta_any(resource: &DeltaResource) -> &prost_types::Any {
    resource
        .resource
        .as_ref()
        .expect("validate_delta_resource checked resource presence")
}

fn ttl_duration(resource: &DeltaResource) -> Result<Option<Duration>, String> {
    resource
        .ttl
        .as_ref()
        .map(|ttl| {
            u64::try_from(ttl.seconds)
                .ok()
                .and_then(|seconds| {
                    Duration::new(seconds, ttl.nanos as u32).checked_add(Duration::ZERO)
                })
                .filter(|duration| !duration.is_zero())
                .ok_or_else(|| "ttl must be a positive finite duration".to_string())
        })
        .transpose()
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
        DeltaApplyError::AliasConflict(name) => {
            format!("{type_name} delta response has conflicting alias `{name}`")
        }
    }
}

/// Where a newly assembled snapshot goes once every resource in a response
/// has lowered cleanly. An injected callback, so this crate does not depend on
/// `proxy-core`'s publisher.
///
/// Rust note: a boxed `FnMut` returning a boxed future, because the closure
/// lives in a struct field and is called from behind `&mut self`.
/// `Pin<Box<dyn Future>>` names "some future I will not spell out" there. It
/// is async because the real publish runs after the cluster manager's own
/// await, so the seam must be able to await too.
///
/// An `Err` here is the NACK's `error_detail` (S8). It rejects the response
/// and restores the applier's resource sets to their pre-response state, because
/// a cluster whose transport socket cannot be built is only found at install time.
pub type Publish = Box<
    dyn FnMut(Arc<ConfigSnapshot>) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>>
        + Send,
>;

/// Where a newly assembled EDS resource's endpoints go once they lower
/// cleanly. The counterpart to [`Publish`] for endpoints, and injected for the
/// same reason.
///
/// The first parameter is a **cluster name** (`Cluster.name`), not the EDS
/// resource name. Envoy allows the two to differ, and several clusters may
/// share one resource, so `on_eds_response` resolves names before calling this.
///
/// Returns `Result` because the cluster manager can refuse endpoints it cannot
/// install (for example a DNS cluster fed unresolvable endpoints). Such a
/// response must NACK rather than ACK a change that never took effect.
pub type PublishEndpoints = Box<
    dyn FnMut(String, Vec<EndpointIR>) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>>
        + Send,
>;

/// One accepted SDS change for the live TLS sink. Removals are explicit events
/// so sinks can evict cached payloads and return consumers to their
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
/// lowered from them.
///
/// Rust note: `PartialEq` is hand-written and compares ONLY `raw`. That is
/// safe because `ir` is a pure function of `raw`, so equal bytes imply equal
/// IR. Envoy also hashes the resource rather than diffing the parsed config.
/// The IR types do not derive `PartialEq`, which is another reason to compare
/// bytes. Do not extend this pattern to fields that are not pure functions of
/// `raw`.
#[derive(Debug)]
struct Entry<T> {
    raw: Vec<u8>,
    ir: Arc<T>,
}

/// Compares only worker-visible identities, ignoring the snapshot version. A
/// listener staged behind missing RDS must not wake workers.
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

// Rust note: written by hand because `#[derive(Clone)]` would demand
// `T: Clone`, and the IR types are deliberately not `Clone`. Cloning an
// entry only bumps the `Arc`.
impl<T> Clone for Entry<T> {
    fn clone(&self) -> Self {
        Self {
            raw: self.raw.clone(),
            ir: Arc::clone(&self.ir),
        }
    }
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

/// The response types whose apply ends in a [`Publish`] call, and so can be
/// refused after their resource sets already changed.
fn publishes_snapshot(type_url: &str) -> bool {
    matches!(type_url, CDS_TYPE_URL | LDS_TYPE_URL | RDS_TYPE_URL)
}

/// Pre-response state [`ResourceApplier::restore`] puts back when a publish
/// is refused.
struct PublishCheckpoint {
    clusters: SotwSet<Entry<ClusterConfig>>,
    listeners: SotwSet<Entry<ListenerConfig>>,
    routes: SotwSet<Entry<RouteTable>>,
    active_dynamic_listeners: std::collections::HashMap<String, Arc<ListenerConfig>>,
    delta_versions: BTreeSet<(String, String, String)>,
}

/// Turns accepted `DiscoveryResponse`s into published [`ConfigSnapshot`]s.
///
/// Holds one [`SotwSet`] per resource type. CDS and LDS are seeded with the
/// bootstrap's names as an immune static set (`store.rs` rule 3). The last
/// published snapshot is kept so a no-op response has something to leave alone.
pub struct ResourceApplier {
    /// The static bootstrap snapshot. Never mutated. Published snapshots copy
    /// their static parts from here.
    base: Arc<ConfigSnapshot>,
    clusters: SotwSet<Entry<ClusterConfig>>,
    listeners: SotwSet<Entry<ListenerConfig>>,
    /// RDS resources are per-name: a response omitting an unrelated route
    /// must not un-warm its listener (S8).
    routes: SotwSet<Entry<RouteTable>>,
    /// Last-good dynamic listeners exposed to workers, as opposed to the latest
    /// LDS desired set in `listeners`. A replacement still waiting on RDS must
    /// not replace a live listener with an unrouteable one.
    active_dynamic_listeners: std::collections::HashMap<String, Arc<ListenerConfig>>,
    /// EDS's own set. `PerName`, not `FullState`: a `ClusterLoadAssignment`
    /// response carries only the assignments being (re)declared now, so an
    /// absent one must not read as removal (S8).
    ///
    /// The static-name set is deliberately EMPTY. An EDS resource name is a
    /// `service_name`, not a `Cluster.name`, and an EDS cluster is declared
    /// statically yet fed through this set. Seeding it from `base.clusters`
    /// would shadow exactly that case.
    endpoints: SotwSet<Entry<Vec<EndpointIR>>>,
    /// SDS's own set. `PerName`, like `endpoints`, because absence is not
    /// removal (S8).
    ///
    /// The static-name set is EMPTY for a similar reason. Whether a listener
    /// uses a static or dynamic secret depends on whether its `SdsSecretConfig`
    /// sets `sds_config`, not on which name arrived first.
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
    /// Last resource versions, used to validate payload-free TTL heartbeats.
    delta_versions: BTreeSet<(String, String, String)>,
    ttl_clock: Arc<dyn Fn() -> Instant + Send + Sync>,
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
            // Empty static-name sets on purpose; see the field docs.
            endpoints: SotwSet::new(SetSemantics::PerName, BTreeSet::new()),
            secrets: SotwSet::new(SetSemantics::PerName, BTreeSet::new()),
            current: Arc::clone(&base),
            base,
            publish,
            endpoint_sink: None,
            secret_sink: None,
            initialization_sink: None,
            delta_versions: BTreeSet::new(),
            ttl_clock: Arc::new(Instant::now),
        }
    }

    /// Wire the sink accepted EDS endpoints are handed to. A consuming builder,
    /// so existing callers of `new` keep compiling. Without it, EDS responses
    /// are refused by name (AGENTS.md invariant 1's shape) rather than silently
    /// dropped.
    pub fn with_endpoint_sink(mut self, sink: PublishEndpoints) -> Self {
        self.endpoint_sink = Some(sink);
        self
    }

    /// Wire the sink accepted SDS secrets are handed to. Same builder shape as
    /// [`ResourceApplier::with_endpoint_sink`].
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

    /// Inject a monotonic clock for deterministic TTL tests.
    pub fn with_ttl_clock(mut self, clock: Arc<dyn Fn() -> Instant + Send + Sync>) -> Self {
        self.ttl_clock = clock;
        self
    }

    /// The snapshot most recently published, for tests and for
    /// `/config_dump`.
    pub fn current(&self) -> &Arc<ConfigSnapshot> {
        &self.current
    }

    /// The EDS resource names the current snapshot needs a subscription for:
    /// every cluster, static or dynamic, whose `eds_cluster_config` names one.
    /// [`ResponseHandler::desired_names`] reads this after each response.
    pub fn eds_resource_names(&self) -> BTreeSet<String> {
        self.current
            .clusters
            .values()
            .filter_map(|cluster| cluster.eds.as_ref().map(|eds| eds.service_name.clone()))
            .collect()
    }

    /// Every secret name a listener in the current snapshot subscribes to, from
    /// both `filter_chains` and `default_filter_chain`. The `BTreeSet`
    /// deduplicates names shared across chains and listeners, and orders them.
    ///
    /// Lowering refuses the name-only form (it would mean
    /// `static_resources.secrets`, still a stub), so every name here is a real
    /// ADS subscription.
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

    /// RDS names come from the latest LDS set, not `current`. A listener still
    /// waiting for its first route table is absent from the worker snapshot but
    /// must still keep its RDS subscription alive.
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
    /// Routing is by the response's own `type_url`. CDS, LDS and RDS publish
    /// only warmed listeners. EDS and SDS use their dedicated sinks.
    ///
    /// Async because publishing awaits, and the ACK must not be sent until the
    /// apply has finished ([`AdsClient::run_once`](crate::client::AdsClient::run_once)).
    pub async fn on_response(&mut self, resp: &DiscoveryResponse) -> Verdict {
        let checkpoint = publishes_snapshot(&resp.type_url).then(|| self.checkpoint());
        let verdict = match resp.type_url.as_str() {
            CDS_TYPE_URL => self.on_cds_response(resp).await,
            LDS_TYPE_URL => self.on_lds_response(resp).await,
            EDS_TYPE_URL => self.on_eds_response(resp).await,
            SDS_TYPE_URL => self.on_sds_response(resp).await,
            RDS_TYPE_URL => self.on_rds_response(resp).await,
            other => Verdict::Reject(format!("unknown ADS type_url `{other}`")),
        };
        if let (Verdict::Reject(_), Some(checkpoint)) = (&verdict, checkpoint) {
            self.restore(checkpoint);
        }
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

        // Envoy treats NOT_FOUND resource errors as explicit removals. Fold
        // them in up front so duplicate checks and sink rollback stay shared.
        let mut normalized = response.clone();
        for (index, resource_error) in response.resource_errors.iter().enumerate() {
            let path = format!("delta_response.resource_errors[{index}]");
            let Some(resource_name) = resource_error.resource_name.as_ref() else {
                return Verdict::Reject(format!("{path}.resource_name must be set"));
            };
            if resource_name.name.is_empty() {
                return Verdict::Reject(format!("{path}.resource_name.name must not be empty"));
            }
            let Some(error_detail) = resource_error.error_detail.as_ref() else {
                return Verdict::Reject(format!("{path}.error_detail must be set"));
            };
            if error_detail.code != 5 {
                return Verdict::Reject(format!(
                    "{path}.error_detail.code `{}` is not NOT_FOUND: {}",
                    error_detail.code, error_detail.message
                ));
            }
            normalized
                .removed_resources
                .push(resource_name.name.clone());
        }
        for (index, resource) in response.resources.iter().enumerate() {
            if let Err(error) = validate_delta_resource(resource, index, &response.type_url) {
                return Verdict::Reject(error);
            }
        }

        let checkpoint = publishes_snapshot(&normalized.type_url).then(|| self.checkpoint());
        let verdict = match normalized.type_url.as_str() {
            CDS_TYPE_URL => self.on_delta_cds_response(&normalized).await,
            LDS_TYPE_URL => self.on_delta_lds_response(&normalized).await,
            RDS_TYPE_URL => self.on_delta_rds_response(&normalized).await,
            EDS_TYPE_URL => self.on_delta_eds_response(&normalized).await,
            SDS_TYPE_URL => self.on_delta_sds_response(&normalized).await,
            other => Verdict::Reject(format!("unknown delta ADS type_url `{other}`")),
        };
        if let (Verdict::Reject(_), Some(checkpoint)) = (&verdict, checkpoint) {
            self.restore(checkpoint);
        }
        if verdict == Verdict::Accept {
            self.emit_initialization_event(&response.type_url).await;
        }
        verdict
    }

    /// Remove resources whose delta TTL deadline has passed and notify same
    /// downstream sinks used by explicit delta removals. Caller owns polling
    /// cadence; no timer task is created inside the applier.
    pub async fn expire_ttl(&mut self, now: Instant) -> Verdict {
        let mut verdict = Verdict::Accept;

        for (type_url, kind) in [
            (CDS_TYPE_URL, "cluster"),
            (LDS_TYPE_URL, "listener"),
            (RDS_TYPE_URL, "route configuration"),
        ] {
            let names = match type_url {
                CDS_TYPE_URL => self.clusters.expired(now),
                LDS_TYPE_URL => self.listeners.expired(now),
                _ => self.routes.expired(now),
            };
            if names.is_empty() {
                continue;
            }
            let outcome = match type_url {
                CDS_TYPE_URL => self.clusters.apply_delta_named(Vec::new(), &names),
                LDS_TYPE_URL => self.listeners.apply_delta_named(Vec::new(), &names),
                _ => self.routes.apply_delta_named(Vec::new(), &names),
            };
            let Ok(outcome) = outcome else {
                return Verdict::Reject(format!("{kind} TTL expiration could not be applied"));
            };
            self.delta_versions
                .retain(|(ty, name, _)| ty != type_url || !names.iter().any(|n| n == name));
            if self.finish(outcome, kind).await != Verdict::Accept {
                verdict = Verdict::Reject(format!("{kind} TTL expiration publish failed"));
            }
        }

        let endpoint_names = self.endpoints.expired(now);
        if !endpoint_names.is_empty() {
            let previous = self.endpoints.clone();
            let outcome = self
                .endpoints
                .apply_delta_named(Vec::new(), &endpoint_names)
                .expect("empty delta with known names cannot fail");
            let mut failures = Vec::new();
            let removals: Vec<_> = outcome
                .removed
                .iter()
                .map(|name| (name.clone(), self.eds_clusters_for(name)))
                .collect();
            if let Some(sink) = self.endpoint_sink.as_mut() {
                for (name, clusters) in removals {
                    for cluster in clusters {
                        if let Err(error) = sink(cluster.clone(), Vec::new()).await {
                            failures.push(format!("{cluster} (resource `{name}`): {error}"));
                        }
                    }
                }
            } else {
                failures.push("EDS endpoint sink is not wired".to_string());
            }
            if failures.is_empty() {
                self.delta_versions.retain(|(ty, name, _)| {
                    ty != EDS_TYPE_URL || !endpoint_names.iter().any(|n| n == name)
                });
            } else {
                self.endpoints = previous;
                verdict = Verdict::Reject(format!(
                    "EDS TTL expiration failed: {}",
                    failures.join("; ")
                ));
            }
        }

        let secret_names = self.secrets.expired(now);
        if !secret_names.is_empty() {
            let previous = self.secrets.clone();
            let outcome = self
                .secrets
                .apply_delta_named(Vec::new(), &secret_names)
                .expect("empty delta with known names cannot fail");
            let mut failures = Vec::new();
            if let Some(sink) = self.secret_sink.as_mut() {
                for name in &outcome.removed {
                    if let Err(error) = sink(SecretUpdate::Remove { name: name.clone() }).await {
                        failures.push(format!("{name}: {error}"));
                    }
                }
            } else {
                failures.push("SDS secret sink is not wired".to_string());
            }
            if failures.is_empty() {
                self.delta_versions.retain(|(ty, name, _)| {
                    ty != SDS_TYPE_URL || !secret_names.iter().any(|n| n == name)
                });
            } else {
                self.secrets = previous;
                verdict = Verdict::Reject(format!(
                    "SDS TTL expiration failed: {}",
                    failures.join("; ")
                ));
            }
        }

        verdict
    }

    fn heartbeat_or_payload(
        &mut self,
        type_url: &str,
        resource: &DeltaResource,
    ) -> Result<bool, String> {
        if resource.resource.is_some() {
            return Ok(false);
        }
        if !self.delta_versions.contains(&(
            type_url.to_string(),
            resource.name.clone(),
            resource.version.clone(),
        )) {
            return Err(format!(
                "delta_response.resources heartbeat for `{}` has no matching resource version",
                resource.name
            ));
        }
        ttl_duration(resource)?;
        if !matches!(
            type_url,
            CDS_TYPE_URL | LDS_TYPE_URL | RDS_TYPE_URL | EDS_TYPE_URL | SDS_TYPE_URL
        ) {
            return Err(format!("unknown delta ADS type_url `{type_url}`"));
        }
        Ok(true)
    }

    fn record_ttls(&mut self, type_url: &str, resources: &[DeltaResource]) {
        let now = (self.ttl_clock)();
        for resource in resources {
            self.delta_versions.remove(&(
                type_url.to_string(),
                resource.name.clone(),
                String::new(),
            ));
            self.delta_versions
                .retain(|(ty, name, _)| ty != type_url || name != &resource.name);
            self.delta_versions.insert((
                type_url.to_string(),
                resource.name.clone(),
                resource.version.clone(),
            ));
            let deadline = resource
                .ttl
                .as_ref()
                .and_then(|_| ttl_duration(resource).ok())
                .flatten()
                .map(|ttl| now + ttl);
            match type_url {
                CDS_TYPE_URL => {
                    if let Some(d) = deadline {
                        self.clusters.set_expiration(resource.name.clone(), d)
                    } else {
                        self.clusters.clear_expiration(&resource.name)
                    }
                }
                LDS_TYPE_URL => {
                    if let Some(d) = deadline {
                        self.listeners.set_expiration(resource.name.clone(), d)
                    } else {
                        self.listeners.clear_expiration(&resource.name)
                    }
                }
                RDS_TYPE_URL => {
                    if let Some(d) = deadline {
                        self.routes.set_expiration(resource.name.clone(), d)
                    } else {
                        self.routes.clear_expiration(&resource.name)
                    }
                }
                EDS_TYPE_URL => {
                    if let Some(d) = deadline {
                        self.endpoints.set_expiration(resource.name.clone(), d)
                    } else {
                        self.endpoints.clear_expiration(&resource.name)
                    }
                }
                SDS_TYPE_URL => {
                    if let Some(d) = deadline {
                        self.secrets.set_expiration(resource.name.clone(), d)
                    } else {
                        self.secrets.clear_expiration(&resource.name)
                    }
                }
                _ => {}
            }
        }
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
        let resources = response.resources.clone();
        let mut pairs = Vec::with_capacity(resources.len());
        for (index, resource) in resources.iter().enumerate() {
            if self.heartbeat_or_payload(CDS_TYPE_URL, resource).is_err() {
                return Verdict::Reject(format!(
                    "delta_response.resources[{index}].resource heartbeat has no matching resource version"
                ));
            }
            if resource.resource.is_none() {
                continue;
            }
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
                resource.aliases.clone(),
            ));
        }
        let outcome = match self
            .clusters
            .apply_delta_named(pairs, &response.removed_resources)
        {
            Ok(outcome) => outcome,
            Err(error) => return Verdict::Reject(delta_apply_error("CDS", error)),
        };
        self.record_ttls(CDS_TYPE_URL, &response.resources);
        self.finish(outcome, "cluster").await
    }

    async fn on_delta_lds_response(&mut self, response: &DeltaDiscoveryResponse) -> Verdict {
        let resources = response.resources.clone();
        let mut pairs = Vec::with_capacity(resources.len());
        for (index, resource) in resources.iter().enumerate() {
            if self.heartbeat_or_payload(LDS_TYPE_URL, resource).is_err() {
                return Verdict::Reject(format!(
                    "delta_response.resources[{index}].resource heartbeat has no matching resource version"
                ));
            }
            if resource.resource.is_none() {
                continue;
            }
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
                resource.aliases.clone(),
            ));
        }
        let outcome = match self
            .listeners
            .apply_delta_named(pairs, &response.removed_resources)
        {
            Ok(outcome) => outcome,
            Err(error) => return Verdict::Reject(delta_apply_error("LDS", error)),
        };
        self.record_ttls(LDS_TYPE_URL, &response.resources);
        self.finish(outcome, "listener").await
    }

    async fn on_delta_rds_response(&mut self, response: &DeltaDiscoveryResponse) -> Verdict {
        let resources = response.resources.clone();
        let mut pairs = Vec::with_capacity(resources.len());
        for (index, resource) in resources.iter().enumerate() {
            if self.heartbeat_or_payload(RDS_TYPE_URL, resource).is_err() {
                return Verdict::Reject(format!(
                    "delta_response.resources[{index}].resource heartbeat has no matching resource version"
                ));
            }
            if resource.resource.is_none() {
                continue;
            }
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
                resource.aliases.clone(),
            ));
        }
        let outcome = match self
            .routes
            .apply_delta_named(pairs, &response.removed_resources)
        {
            Ok(outcome) => outcome,
            Err(error) => return Verdict::Reject(delta_apply_error("RDS", error)),
        };
        self.record_ttls(RDS_TYPE_URL, &response.resources);
        self.finish(outcome, "route configuration").await
    }

    async fn on_delta_eds_response(&mut self, response: &DeltaDiscoveryResponse) -> Verdict {
        if self.endpoint_sink.is_none() {
            return Verdict::Reject(format!(
                "EDS (`{EDS_TYPE_URL}`) is not applied: this ResourceApplier has no endpoint sink wired"
            ));
        }
        let resources = response.resources.clone();
        let mut pairs = Vec::with_capacity(resources.len());
        for (index, resource) in resources.iter().enumerate() {
            if self.heartbeat_or_payload(EDS_TYPE_URL, resource).is_err() {
                return Verdict::Reject(format!(
                    "delta_response.resources[{index}].resource heartbeat has no matching resource version"
                ));
            }
            if resource.resource.is_none() {
                continue;
            }
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
                resource.aliases.clone(),
            ));
        }

        let previous = self.endpoints.clone();
        let outcome = match self
            .endpoints
            .apply_delta_named(pairs, &response.removed_resources)
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
            self.record_ttls(EDS_TYPE_URL, &response.resources);
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
        let resources = response.resources.clone();
        let mut pairs = Vec::with_capacity(resources.len());
        for (index, resource) in resources.iter().enumerate() {
            if self.heartbeat_or_payload(SDS_TYPE_URL, resource).is_err() {
                return Verdict::Reject(format!(
                    "delta_response.resources[{index}].resource heartbeat has no matching resource version"
                ));
            }
            if resource.resource.is_none() {
                continue;
            }
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
                resource.aliases.clone(),
            ));
        }
        let Some(sink) = self.secret_sink.as_mut() else {
            return Verdict::Reject(format!(
                "SDS (`{SDS_TYPE_URL}`) is not applied: this ResourceApplier has no secret sink wired"
            ));
        };
        let previous = self.secrets.clone();
        let outcome = match self
            .secrets
            .apply_delta_named(pairs, &response.removed_resources)
        {
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
            self.record_ttls(SDS_TYPE_URL, &response.resources);
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
            Err(ApplyError::AliasConflict(name)) => {
                return Verdict::Reject(format!("CDS response has conflicting alias: {name}"));
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
            Err(ApplyError::AliasConflict(name)) => {
                return Verdict::Reject(format!("LDS response has conflicting alias: {name}"));
            }
        };
        self.finish(outcome, "listener").await
    }

    /// RDS is `PerName`: an omitted route is not a deletion. A changed route
    /// can promote a staged listener or rebuild a live one, but never tears
    /// down an unrelated listener.
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
            Err(ApplyError::AliasConflict(name)) => {
                return Verdict::Reject(format!("RDS response has conflicting alias: {name}"));
            }
        };
        self.finish(outcome, "route configuration").await
    }

    /// EDS has no `finish` call. An accepted endpoint update never touches
    /// `ConfigSnapshot`. It goes to [`PublishEndpoints`] once per cluster fed by
    /// an `added` or `updated` resource, never for `unchanged` ones.
    ///
    /// Each resource is resolved to every cluster in `self.current` whose
    /// `eds.service_name` names it. The sink receives the cluster's own name,
    /// never the resource name.
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
            Err(ApplyError::AliasConflict(name)) => {
                return Verdict::Reject(format!("EDS response has conflicting alias: {name}"));
            }
        };

        // `apply` already recorded the added/updated names before the sink
        // ran. Forget exactly the resource names whose sink call failed, so an
        // identical retransmission reads as `added` and reaches the sink again.
        // Successful names stay recorded. The store is keyed by resource name;
        // only the sink call is keyed by cluster name.
        let mut failed_resources: BTreeSet<String> = BTreeSet::new();
        let mut failure_detail: Vec<String> = Vec::new();
        for name in outcome.added.iter().chain(outcome.updated.iter()) {
            let entry = self
                .endpoints
                .get(name)
                .expect("a name SotwSet::apply just reported added/updated must be present");
            let endpoints = (*entry.ir).clone();

            // Resource name -> cluster name(s), from the CURRENT snapshot.
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
                // An unmatched resource is the control plane's bug. NACKing the
                // whole response would stall the resources that did match.
                // Warn, as `shadowed_by_static` does in `finish`.
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

    /// Like `on_eds_response`, but simpler. `Secret.name` is passed to the sink
    /// unchanged, since nothing in the snapshot maps it to another name. Mapping
    /// a name to the chain it serves is the sink's job. There is no `finish`
    /// call: an accepted secret never touches `ConfigSnapshot`.
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
            Err(ApplyError::AliasConflict(name)) => {
                return Verdict::Reject(format!("SDS response has conflicting alias: {name}"));
            }
        };

        // Same store fix-up as `on_eds_response`: forget the names whose sink
        // call failed, or an identical retransmission would stay `unchanged`.
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

    /// Shared tail of the CDS/LDS/RDS handlers. Warns on shadowed names,
    /// publishes only if something changed, and accepts. A `SotwSet::apply`
    /// that ran at all means every resource lowered cleanly.
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
            // The caller restores its checkpoint on this rejection, so the
            // sets this response changed do not outlive the refusal.
            if let Err(error) = (self.publish)(Arc::clone(&snapshot)).await {
                return Verdict::Reject(error);
            }
            self.current = snapshot;
        }
        Verdict::Accept
    }

    /// The state a CDS, LDS or RDS response changes before [`Publish`] can
    /// refuse it. A refused response must have no effect (S8), so a
    /// retransmission cannot compare `unchanged` and be ACKed uninstalled.
    fn checkpoint(&self) -> PublishCheckpoint {
        PublishCheckpoint {
            clusters: self.clusters.clone(),
            listeners: self.listeners.clone(),
            routes: self.routes.clone(),
            active_dynamic_listeners: self.active_dynamic_listeners.clone(),
            delta_versions: self.delta_versions.clone(),
        }
    }

    fn restore(&mut self, checkpoint: PublishCheckpoint) {
        self.clusters = checkpoint.clusters;
        self.listeners = checkpoint.listeners;
        self.routes = checkpoint.routes;
        self.active_dynamic_listeners = checkpoint.active_dynamic_listeners;
        self.delta_versions = checkpoint.delta_versions;
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

    /// Promote an LDS generation only once every listener in it has its RDS
    /// dependencies. Until then keep the whole last-good set. Keeping only the
    /// same-named listener would withdraw a renamed old listener before its
    /// replacement is warm (make-before-break). An explicitly empty generation
    /// is a deliberate removal and promotes at once.
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
    /// The merge is [`ConfigSnapshot::with_dynamic_resources`], not a struct
    /// literal, which would name every field and defeat the IR readership scan
    /// in `crates/proxy-config/tests/ir_readership.rs`.
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

/// `ResourceApplier` is the [`ResponseHandler`] itself. Callers pass it to
/// [`crate::client::AdsClient::run`] or `run_once` directly.
impl ResponseHandler for ResourceApplier {
    fn handle(&mut self, resp: &DiscoveryResponse) -> impl Future<Output = Verdict> + Send {
        self.on_response(resp)
    }

    /// Name sets exist for EDS, RDS and SDS. CDS and LDS are wildcard
    /// subscriptions, so this returns `None` for them. SDS names come from the
    /// snapshot's `certificate_sds_names`, as EDS names come from its clusters.
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

/// Acceptance tests for `on_sds_response`, colocated here like `store.rs`'s
/// own tests. Fixtures build the proto by hand and drive `on_response`.
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
            Box::pin(std::future::ready(Ok(())))
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

    /// PerName semantics (S8: SDS absence is not removal). A third response
    /// resending `cert-a`'s identical bytes must stay `unchanged` and skip the
    /// sink, even though the middle response omitted `cert-a`.
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

    /// A sink failure must `forget` the name, or an identical retransmission
    /// would stay `unchanged` and the secret would never be published.
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
