//! The seam that maps an SDS secret NAME to the
//! [`DownstreamTlsFactory`] instances that named it, so an accepted secret
//! (`ResourceApplier`'s `PublishSecrets` sink, `crates/proxy-xds/src/apply.rs`)
//! actually reaches a serving TLS chain instead of stopping at the sink.
//!
//! Named `SdsSecretRegistry`, not `SecretRegistry` -- `listener.rs` already
//! threads a `registry` that is a `ConnectionRegistry` and a `FilterRegistry`,
//! and a third bare "registry" in the same argument lists would be a reading
//! hazard.
//!
//! # Why both directions
//!
//! A secret can arrive before or after the factory that needs it exists:
//! - **Factory first, secret later** is the ordinary case: a worker binds a
//!   listener at startup, and the control plane delivers the certificate
//!   afterwards. [`SdsSecretRegistry::publish`] handles this -- it pushes
//!   straight to every already-registered factory.
//! - **Secret first, factory later** is the *normal* case, not an edge case:
//!   workers bind on their own schedule, and an accept loop rebuilds its TLS
//!   factories lazily whenever it notices the config snapshot's version
//!   changed (`listener.rs`'s `spawn_accept_loop`). A secret the control
//!   plane already delivered before that rebuild must not wait for a second,
//!   unprompted resend. [`SdsSecretRegistry::register`] handles this -- it
//!   replays the last delivered certs for a name immediately, before
//!   returning, if any are cached.
//!
//! Getting only one of these two right leaves an SDS-named chain unserved in
//! exactly the ordering that isn't exercised by whichever test happens to be
//! written -- see `crates/proxy-core/tests/tls.rs`'s "publish-then-serve" and
//! "late registration" tests, which pin both orderings independently.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

use proxy_config::ir::{SecretName, TlsCertificateIR, ValidationContextIR};

use super::{DownstreamTlsFactory, TlsBuildError};

/// Everything the registry holds, behind one lock -- see [`SdsSecretRegistry`]
/// for why a single `Mutex` (not two) is correct here: `register` and
/// `publish` both need to read one field while mutating the other, and
/// keeping them under one lock is what makes "check `delivered`, then act on
/// `factories`" atomic with respect to a concurrent call on the other name.
struct Inner {
    /// Who to push a newly delivered secret to, by `Secret.name`.
    ///
    /// Rust note: `Weak`, not `Arc`. A factory's owner is the accept loop's
    /// `Rc<ListenerTls>` cache (`listener.rs`), which is replaced -- not
    /// mutated -- every time that loop rebuilds on a snapshot version change,
    /// or when a listener is removed entirely (`reconcile`). If this map held
    /// `Arc<DownstreamTlsFactory>`, every rebuild would leave the OLD
    /// factory alive forever (this registry would be the only thing still
    /// referencing it) and leak one entry per rebuild for the life of the
    /// process. `Weak::upgrade` turns "is this factory still alive" into an
    /// `Option`, so a dead entry costs nothing beyond eventually being
    /// pruned -- never a strong reference this registry has no business
    /// holding.
    certificate_factories: HashMap<SecretName, Vec<Weak<DownstreamTlsFactory>>>,
    validation_factories: HashMap<SecretName, Vec<Weak<DownstreamTlsFactory>>>,
    /// The last certs delivered for each name, so a factory that registers
    /// AFTER a secret already arrived (the normal case -- see the module
    /// doc) can be caught up immediately instead of waiting for a resend
    /// that may never come.
    delivered_certificates: HashMap<SecretName, Vec<TlsCertificateIR>>,
    delivered_validation_contexts: HashMap<SecretName, ValidationContextIR>,
}

/// Maps an SDS `Secret.name` to the [`DownstreamTlsFactory`] instances
/// currently serving it, and replays the last delivered certificate set to a
/// factory that registers late. See the module doc for the two orderings
/// this exists to cover.
pub struct SdsSecretRegistry {
    inner: Mutex<Inner>,
}

impl Default for SdsSecretRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SdsSecretRegistry {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                certificate_factories: HashMap::new(),
                validation_factories: HashMap::new(),
                delivered_certificates: HashMap::new(),
                delivered_validation_contexts: HashMap::new(),
            }),
        }
    }

    /// Register `factory` as a server of every name in `names` (a chain's
    /// `DownstreamTlsSpec::certificate_sds_names`), and immediately hot-swap
    /// in any certs already delivered for one of those names -- see the
    /// module doc's "secret first, factory later" case. `context` is used
    /// only for that immediate hot-swap's error message, the same shape
    /// `DownstreamTlsFactory::build`'s own `context` parameter uses.
    ///
    /// A late-registration hot-swap failure (a cached secret that this
    /// factory's crypto provider can't load, for instance) is returned to
    /// the caller rather than swallowed -- `listener.rs`'s callers already
    /// treat a `TlsBuildError` from factory construction as a startup/
    /// reconcile failure, and a registry-driven swap failing is the same
    /// kind of problem.
    pub fn register(
        &self,
        names: &[SecretName],
        factory: &Arc<DownstreamTlsFactory>,
        context: &str,
    ) -> Result<(), TlsBuildError> {
        let mut inner = self.inner.lock().expect("SdsSecretRegistry mutex poisoned");
        let weak = Arc::downgrade(factory);
        for name in names {
            // Rust note: pruned here (not just in `publish`) so a name that
            // has cycled through many dead factories (repeated rebuilds of a
            // chain that never got fresh secrets) doesn't grow this `Vec`
            // without bound -- `Weak::strong_count` is enough to tell a dead
            // entry apart from a live one without paying for a full
            // `upgrade` on each.
            let list = inner.certificate_factories.entry(name.clone()).or_default();
            list.retain(|w| w.strong_count() > 0);
            list.push(weak.clone());
        }
        // Late registration: replay whatever is already cached for any of
        // these names. Deliberately a second loop (not folded into the one
        // above) -- `inner.delivered` (read) and `inner.factories` (written)
        // are different fields of the same `Inner`, so borrowing both at
        // once from `&mut inner` is fine, but keeping the two concerns in
        // separate loops reads clearer than interleaving them.
        for name in names {
            if let Some(certs) = inner.delivered_certificates.get(name) {
                factory.update_certificates(certs, context)?;
            }
        }
        Ok(())
    }

    /// Register a factory for a downstream
    /// `validation_context_sds_secret_config`. This deliberately has a
    /// separate map/cache from certificate registration: an SDS name denotes
    /// one secret *kind*, and delivering a certificate where a trust anchor
    /// is expected must never accidentally mutate the other reload seam.
    pub fn register_validation_context(
        &self,
        name: &str,
        factory: &Arc<DownstreamTlsFactory>,
        context: &str,
    ) -> Result<(), TlsBuildError> {
        let mut inner = self.inner.lock().expect("SdsSecretRegistry mutex poisoned");
        let list = inner
            .validation_factories
            .entry(name.to_string())
            .or_default();
        list.retain(|w| w.strong_count() > 0);
        list.push(Arc::downgrade(factory));
        if let Some(validation) = inner.delivered_validation_contexts.get(name) {
            factory.update_validation_context(validation, context)?;
        }
        Ok(())
    }

    /// Record `certs` as the current delivery for `name`, and hot-swap every
    /// live factory registered under it -- see the module doc's "factory
    /// first, secret later" case. A name with no registered factory yet is
    /// `Ok(())`: the certs are cached (so a later `register` catches up
    /// immediately) and this is logged at `debug`, not treated as an error --
    /// a control plane is allowed to push a secret before any listener that
    /// names it has bound.
    ///
    /// Returns `Err` naming `name` if hot-swapping any live factory fails --
    /// that becomes an SDS NACK one layer up
    /// (`crates/proxy/src/main.rs`'s secret sink), which is the right answer
    /// to a control plane sending a certificate this proxy cannot load: ACKing
    /// it would tell the control plane the proxy is serving something it
    /// is not.
    pub fn publish(&self, name: &str, certs: Vec<TlsCertificateIR>) -> Result<(), String> {
        let mut inner = self.inner.lock().expect("SdsSecretRegistry mutex poisoned");
        inner.delivered_certificates.insert(name.to_string(), certs);

        // Rust note: `list` below is cloned (not held as a borrow of
        // `inner.factories`) specifically so the borrow checker sees the
        // `factories` and `delivered` borrows as sequential rather than
        // overlapping -- a `Weak` clone is cheap (it just bumps a weak
        // count), so this costs nothing but is what lets us then borrow
        // `inner.delivered` immutably for `certs` below without the two
        // borrows fighting over the same `MutexGuard`.
        let list = inner
            .certificate_factories
            .entry(name.to_string())
            .or_default();
        // Pruning here is what makes a publish to a name whose only
        // registered factory has since been dropped read as "no factories",
        // not as a dangling `Weak` that upgrades to nothing on every call
        // forever -- see the module doc's `Weak` note.
        list.retain(|w| w.strong_count() > 0);
        let list = list.clone();

        let certs = inner
            .delivered_certificates
            .get(name)
            .expect("just inserted this name's entry above");

        let context = format!("SDS secret `{name}`");
        let mut reached = 0usize;
        let mut failures: Vec<String> = Vec::new();
        for weak in list.iter() {
            // Rust note: `upgrade` (not just the `strong_count` check above)
            // -- a concurrent drop between the `retain` and this loop is
            // possible in principle (this lock is held across both, so in
            // practice it isn't here, but `upgrade`'s `Option` is the correct
            // way to handle it regardless of how tight that window is).
            let Some(factory) = weak.upgrade() else {
                continue;
            };
            match factory.update_certificates(certs, &context) {
                Ok(()) => reached += 1,
                Err(err) => failures.push(err.to_string()),
            }
        }

        if !failures.is_empty() {
            return Err(format!(
                "secret `{name}` rejected by {} of its registered TLS chain(s): {}",
                failures.len(),
                failures.join("; ")
            ));
        }

        if reached > 0 {
            tracing::info!(
                secret = name,
                factories = reached,
                "SDS secret delivered: serving TLS chain(s) updated"
            );
        } else {
            tracing::debug!(
                secret = name,
                "SDS secret published with no registered TLS chain yet; cached for a later \
                 registration"
            );
        }
        Ok(())
    }

    /// Record and publish a validation-context SDS secret. The new
    /// `ServerConfig` is built before any factory swaps it in; a bad CA bundle
    /// therefore NACKs while every affected listener retains its previous
    /// trust anchors (or its initial fail-closed pending config).
    pub fn publish_validation_context(
        &self,
        name: &str,
        validation: ValidationContextIR,
    ) -> Result<(), String> {
        let mut inner = self.inner.lock().expect("SdsSecretRegistry mutex poisoned");
        let list = inner
            .validation_factories
            .entry(name.to_string())
            .or_default();
        list.retain(|w| w.strong_count() > 0);
        let list = list.clone();

        let context = format!("SDS validation_context secret `{name}`");
        let mut reached = 0usize;
        let mut failures = Vec::new();
        for weak in &list {
            let Some(factory) = weak.upgrade() else {
                continue;
            };
            match factory.update_validation_context(&validation, &context) {
                Ok(()) => reached += 1,
                Err(err) => failures.push(err.to_string()),
            }
        }
        if !failures.is_empty() {
            return Err(format!(
                "validation_context secret `{name}` rejected by {} registered TLS chain(s): {}",
                failures.len(),
                failures.join("; ")
            ));
        }
        // Cache only a fully accepted value. If construction failed above,
        // retaining an invalid CA would make a later factory registration
        // fail against a secret the control plane has already been NACKed.
        inner
            .delivered_validation_contexts
            .insert(name.to_string(), validation);
        if reached > 0 {
            tracing::info!(
                secret = name,
                factories = reached,
                "SDS validation context delivered: serving TLS trust anchors updated"
            );
        } else {
            tracing::debug!(
                secret = name,
                "SDS validation context published with no registered TLS chain yet; cached for a later registration"
            );
        }
        Ok(())
    }

    /// Evict a delivered SDS secret and return every live consumer of that
    /// name to its fail-closed pending state. Unknown and unregistered names
    /// are successful no-ops, matching delta xDS removal semantics.
    pub fn remove(&self, name: &str) -> Result<(), String> {
        let mut inner = self.inner.lock().expect("SdsSecretRegistry mutex poisoned");

        let validation_factories = inner
            .validation_factories
            .entry(name.to_string())
            .or_default();
        validation_factories.retain(|weak| weak.strong_count() > 0);
        let validation_factories = validation_factories.clone();

        let context = format!("removed SDS secret `{name}`");
        let mut failures = Vec::new();
        for weak in &validation_factories {
            let Some(factory) = weak.upgrade() else {
                continue;
            };
            if let Err(error) = factory.remove_validation_context(&context) {
                failures.push(error.to_string());
            }
        }
        if !failures.is_empty() {
            return Err(format!(
                "secret `{name}` removal rejected by {} registered TLS chain(s): {}",
                failures.len(),
                failures.join("; ")
            ));
        }

        let certificate_factories = inner
            .certificate_factories
            .entry(name.to_string())
            .or_default();
        certificate_factories.retain(|weak| weak.strong_count() > 0);
        let certificate_factories = certificate_factories.clone();
        for weak in &certificate_factories {
            if let Some(factory) = weak.upgrade() {
                factory.remove_certificates();
            }
        }

        inner.delivered_certificates.remove(name);
        inner.delivered_validation_contexts.remove(name);
        tracing::info!(
            secret = name,
            certificate_factories = certificate_factories.len(),
            validation_factories = validation_factories.len(),
            "SDS secret removed: registered TLS chain(s) returned to pending state"
        );
        Ok(())
    }

    /// The number of currently-live factories registered under `name` --
    /// i.e. after pruning dead `Weak`s. Not used by production code; exists
    /// so `crates/proxy-core/tests/tls.rs` can assert the pruning behavior
    /// directly (a plain `pub fn`, not `#[cfg(test)]`, because that test file
    /// compiles as a separate integration-test crate and so cannot see
    /// anything gated on this crate's own `cfg(test)`).
    pub fn registered_factory_count(&self, name: &str) -> usize {
        let mut inner = self.inner.lock().expect("SdsSecretRegistry mutex poisoned");
        let list = inner
            .certificate_factories
            .entry(name.to_string())
            .or_default();
        list.retain(|w| w.strong_count() > 0);
        list.len()
    }
}
