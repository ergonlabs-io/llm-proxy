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
//! 6. **RDS and EDS are out of scope for this increment**, refused by name
//!    rather than silently ignored (ground rule #1's shape): RDS is WP-20
//!    increment 5's own follow-on, EDS is WP-21's.
//!
//! # Ordering is `SotwSet::apply`'s job, not this module's
//!
//! S8's `CDS -> EDS -> LDS -> RDS` apply ordering lives in
//! `SotwSet`/`store.rs`'s own doc; this module does not sequence anything
//! across types -- it maintains one independent [`SotwSet`] per type and
//! only ever touches one of them per call, driven by the response's own
//! `type_url`.

use std::collections::HashMap;
use std::sync::Arc;

use prost::Message;
use proxy_api::envoy::config::cluster::v3::Cluster as ClusterProto;
use proxy_api::envoy::config::listener::v3::Listener as ListenerProto;
use proxy_api::envoy::service::discovery::v3::DiscoveryResponse;
use proxy_config::ir::{ClusterConfig, ConfigSnapshot, ListenerConfig, SnapshotVersion};
use proxy_config::{lower_dynamic_cluster, lower_dynamic_listener};

use crate::client::Validator;
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
/// Rust note: a plain boxed `FnMut`, the same shape as [`Validator`] in
/// `client.rs` and [`crate::client::Sleep`] -- an injected callback rather
/// than a dependency on `proxy-core`'s `ConfigPublisher`, so this crate never
/// pulls in the worker runtime. Wiring the real `ConfigPublisher` in is
/// `crates/proxy/src/main.rs`'s job, not this module's.
pub type Publish = Box<dyn FnMut(Arc<ConfigSnapshot>) + Send>;

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
    pub fn on_response(&mut self, resp: &DiscoveryResponse) -> Verdict {
        match resp.type_url.as_str() {
            CDS_TYPE_URL => self.on_cds_response(resp),
            LDS_TYPE_URL => self.on_lds_response(resp),
            RDS_TYPE_URL => Verdict::Reject(format!(
                "RDS (`{RDS_TYPE_URL}`) is not applied by this increment -- route tables are \
                 WP-20 increment 5's own follow-on"
            )),
            EDS_TYPE_URL => Verdict::Reject(format!(
                "EDS (`{EDS_TYPE_URL}`) is not applied by this increment -- endpoint discovery \
                 is WP-21's"
            )),
            other => Verdict::Reject(format!("unknown ADS type_url `{other}`")),
        }
    }

    /// Consume into the [`Validator`] the ADS client wants.
    ///
    /// Rust note: the closure captures `self` by move (`mut self` in the
    /// signature, not `&mut self`), so calling `into_validator` gives up
    /// ownership of the `ResourceApplier` entirely -- there is no path back
    /// to it except through the `Validator` this returns. That mirrors how
    /// `client.rs`'s own `Validator` is consumed: `AdsClient::run_once` takes
    /// `&mut Validator` and never hands the caller a way to peek behind it.
    pub fn into_validator(mut self) -> Validator {
        Box::new(move |resp: &DiscoveryResponse| self.on_response(resp))
    }

    fn on_cds_response(&mut self, resp: &DiscoveryResponse) -> Verdict {
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
        self.finish(outcome, "cluster")
    }

    fn on_lds_response(&mut self, resp: &DiscoveryResponse) -> Verdict {
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
        self.finish(outcome, "listener")
    }

    /// Common tail of both `on_*_response` methods: warn on anything shadowed
    /// (rule 5), publish a fresh snapshot iff something actually changed
    /// (rule 4), and accept either way -- a `SotwSet::apply` that ran at all
    /// already means every resource in the response lowered cleanly.
    fn finish(&mut self, outcome: ApplyOutcome, kind: &str) -> Verdict {
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
            (self.publish)(Arc::clone(&snapshot));
            self.current = snapshot;
        }
        Verdict::Accept
    }

    /// Build a fresh snapshot: `base`'s non-resource fields unchanged,
    /// listeners/clusters as `base`'s static entries plus whatever each
    /// `SotwSet` currently holds dynamically, version bumped by one from
    /// `current` (the last one actually published).
    fn assemble_snapshot(&self) -> Arc<ConfigSnapshot> {
        let mut listeners: HashMap<String, Arc<ListenerConfig>> = HashMap::new();
        for (name, cfg) in &self.base.listeners {
            listeners.insert(name.clone(), Arc::clone(cfg));
        }
        for name in self.listeners.names() {
            let entry = self
                .listeners
                .get(name)
                .expect("a name SotwSet::names() just returned must be present in the same set");
            // Static names are supposed to be immune (`store.rs` rule 3): a
            // colliding name is reported `shadowed_by_static` and never
            // reaches the dynamic map at all. Assert the invariant rather
            // than assume it -- a bug here would silently let a dynamic
            // listener overwrite a static one instead of refusing it.
            debug_assert!(
                !self.base.listeners.contains_key(name),
                "dynamic listener `{name}` collides with a static one; static names should have \
                 made this shadowed_by_static, never applied"
            );
            listeners.insert(name.to_string(), Arc::clone(&entry.ir));
        }

        let mut clusters: HashMap<String, Arc<ClusterConfig>> = HashMap::new();
        for (name, cfg) in &self.base.clusters {
            clusters.insert(name.clone(), Arc::clone(cfg));
        }
        for name in self.clusters.names() {
            let entry = self
                .clusters
                .get(name)
                .expect("a name SotwSet::names() just returned must be present in the same set");
            debug_assert!(
                !self.base.clusters.contains_key(name),
                "dynamic cluster `{name}` collides with a static one; static names should have \
                 made this shadowed_by_static, never applied"
            );
            clusters.insert(name.to_string(), Arc::clone(&entry.ir));
        }

        Arc::new(ConfigSnapshot {
            listeners,
            clusters,
            routes: self.base.routes.clone(),
            secrets: self.base.secrets.clone(),
            admin: self.base.admin,
            tracing: self.base.tracing.clone(),
            ads: self.base.ads.clone(),
            version: SnapshotVersion(self.current.version.0 + 1),
        })
    }
}
