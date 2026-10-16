//! Maps an SDS secret name to the [`DownstreamTlsFactory`] instances that use it, so an accepted secret (the
//! `PublishSecrets` sink in `crates/proxy-xds/src/apply.rs`) reaches a serving TLS chain instead of stopping at the sink.
//!
//! Named `SdsSecretRegistry`, not `SecretRegistry`: `listener.rs` already threads a `registry` argument, and a third
//! bare "registry" in the same lists would be a reading hazard.
//!
//! # Both orderings
//!
//! - **Factory first, secret later** is the ordinary case: the listener binds at startup and the certificate arrives
//!   afterwards. [`SdsSecretRegistry::publish`] pushes straight to every registered factory.
//! - **Secret first, factory later** is also normal. Workers bind on their own schedule, and an accept loop rebuilds
//!   its TLS factories when the snapshot version changes (`listener.rs`'s `spawn_accept_loop`). A secret delivered
//!   before that rebuild must not wait for a resend. [`SdsSecretRegistry::register`] replays the last delivered certs
//!   for a name before returning.
//!
//! Only one of these handled leaves an SDS-named chain unserved in an ordering the tests do not exercise.
//! `crates/proxy-core/tests/tls.rs` pins both orderings independently.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

use proxy_config::ir::{SecretName, TlsCertificateIR, ValidationContextIR};

use super::{DownstreamTlsFactory, TlsBuildError};

/// Everything the registry holds, behind one lock. `register` and `publish` each read one field while mutating the
/// other, so one `Mutex` makes "check `delivered`, then act on `factories`" atomic.
struct Inner {
    /// Who to push a newly delivered secret to, by `Secret.name`.
    ///
    /// Rust note: `Weak`, not `Arc`. The factory's owner is the accept loop's `Rc<ListenerTls>` cache, which is replaced
    /// on every rebuild or listener removal. An `Arc` here would keep every old factory alive, leaking one entry per
    /// rebuild for the life of the process. `Weak::upgrade` makes a dead entry cost nothing beyond eventual pruning.
    certificate_factories: HashMap<SecretName, Vec<Weak<DownstreamTlsFactory>>>,
    validation_factories: HashMap<SecretName, Vec<Weak<DownstreamTlsFactory>>>,
    /// The last certs delivered per name. A factory that registers after a secret arrived is caught up at once.
    delivered_certificates: HashMap<SecretName, Vec<TlsCertificateIR>>,
    delivered_validation_contexts: HashMap<SecretName, ValidationContextIR>,
}

/// Maps an SDS `Secret.name` to the [`DownstreamTlsFactory`] instances serving it, and replays the last delivered
/// certificate set to a factory that registers late. See the module doc for the two orderings.
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

    /// Registers `factory` as a server of every name in `names` (a chain's `certificate_sds_names`), and immediately
    /// hot-swaps in any certs already delivered for those names. `context` only labels that swap's error message.
    ///
    /// A late-registration swap failure (for example a cached secret this factory's crypto provider cannot load) is
    /// returned, not swallowed. Callers already treat a `TlsBuildError` as a startup or reconcile failure.
    pub fn register(
        &self,
        names: &[SecretName],
        factory: &Arc<DownstreamTlsFactory>,
        context: &str,
    ) -> Result<(), TlsBuildError> {
        let mut inner = self.inner.lock().expect("SdsSecretRegistry mutex poisoned");
        let weak = Arc::downgrade(factory);
        for name in names {
            // Rust note: pruned here, not only in `publish`, so a name cycled through many dead factories does not grow
            // this `Vec` without bound. `Weak::strong_count` tells a dead entry from a live one without an `upgrade`.
            let list = inner.certificate_factories.entry(name.clone()).or_default();
            list.retain(|w| w.strong_count() > 0);
            list.push(weak.clone());
        }
        // Late registration: replay whatever is cached for these names. This is a second loop because `delivered`
        // (read) and `factories` (written) are different fields of `Inner`, so the two loops read more clearly apart.
        for name in names {
            if let Some(certs) = inner.delivered_certificates.get(name) {
                factory.update_certificates(certs, context)?;
            }
        }
        Ok(())
    }

    /// Registers a factory for a downstream `validation_context_sds_secret_config`. It has its own map, so an SDS
    /// name's kind stays fixed: a certificate delivered where a trust anchor is expected must not touch the other seam.
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

    /// Records `certs` as the current delivery for `name` and hot-swaps every live factory registered under it. A
    /// name with no factory yet is `Ok(())`: the certs are cached for a later `register`, and this is logged at
    /// `debug`. A control plane may push a secret before any listener names it.
    ///
    /// `Err` names `name` when a live swap fails. The caller turns that into an SDS NACK, since ACKing a certificate
    /// this proxy cannot load would tell the control plane it is serving something it is not.
    pub fn publish(&self, name: &str, certs: Vec<TlsCertificateIR>) -> Result<(), String> {
        let mut inner = self.inner.lock().expect("SdsSecretRegistry mutex poisoned");
        inner.delivered_certificates.insert(name.to_string(), certs);

        // Rust note: `list` is cloned, not borrowed from `inner.factories`, so the `factories` and `delivered`
        // borrows do not overlap. A `Weak` clone is cheap, and this lets `inner.delivered` be borrowed for `certs`
        // below without fighting over the same `MutexGuard`.
        let list = inner
            .certificate_factories
            .entry(name.to_string())
            .or_default();
        // Pruning here means a name whose only factory was dropped reads as "no factories", not as a dangling `Weak`
        // that upgrades to nothing on every call.
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
            // Rust note: `upgrade` rather than the `strong_count` check above. A drop between the two is possible in
            // principle, and `upgrade`'s `Option` handles it however narrow the window is.
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

    /// Records and publishes a validation-context SDS secret. The new `ServerConfig` is built before any factory
    /// swaps it in, so a bad CA bundle is NACKed while every affected listener keeps its previous trust anchors.
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
        // Cache only a fully accepted value. Caching an invalid CA would make a later factory registration fail against
        // a secret the control plane has already been NACKed for.
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

    /// Evicts a delivered SDS secret and returns every live consumer of that name to its fail-closed pending state.
    /// Unknown and unregistered names are successful no-ops, matching delta xDS removal semantics.
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
}
