//! Runtime core: control/worker runtimes and config propagation,
//! listener manager + filter-chain matching, transport sockets,
//! and the L4 network filter framework.

pub mod admission;
pub mod ads_transport;
pub mod drain;
pub mod filter_chain;
pub mod header_mutation_filter;
pub mod lifecycle;
pub mod listener;
pub mod net_filter;
pub mod runtime;
pub mod tcp_proxy;
pub mod tls;
pub mod tls_inspector;
pub mod transport;

#[cfg(test)]
mod test_ports;

use std::sync::Arc;

use arc_swap::ArcSwap;
use proxy_config::ir::SnapshotVersion;
use proxy_config::ConfigSnapshot;

/// How each worker sees configuration. The control runtime builds immutable snapshots and `store`s them. Workers
/// `load` on connection accept, and react to a `watch` ping for listener socket add and remove. In-flight connections
/// keep their `Arc<ConfigSnapshot>`, which gives Envoy-style drain: old config lives as long as the connections made
/// under it. HTTP connections also [`subscribe`](Self::subscribe) to the published version and close gracefully once a
/// later snapshot replaces theirs, so a rotated provider credential stops being sent (envoy-divergences.md).
///
/// The only way to obtain one from outside this crate is [`runtime::SnapshotHandles::register`], which enrolls it so
/// [`runtime::ConfigPublisher::publish`] can find it. A handle built any other way would silently stop seeing reloads.
/// `WorkerConfigHandle::new` is `pub(crate)`, so this is enforced by the compiler:
///
/// ```compile_fail
/// use std::sync::Arc;
/// use proxy_config::ConfigSnapshot;
/// use proxy_core::WorkerConfigHandle;
///
/// // ERROR: associated function `new` is private.
/// let handle = WorkerConfigHandle::new(Arc::new(ConfigSnapshot::default()));
/// ```
pub struct WorkerConfigHandle {
    snapshot: ArcSwap<ConfigSnapshot>,
    /// The version of `snapshot`, sent after each `store`.
    version: tokio::sync::watch::Sender<SnapshotVersion>,
}

impl WorkerConfigHandle {
    // Rust note: `pub(crate)` on purpose. A handle not enrolled in `runtime::SnapshotHandles` silently stops seeing
    // `publish()`. `SnapshotHandles::register` is the only place that both builds and enrolls, and the compiler refuses
    // the shortcut.
    pub(crate) fn new(initial: Arc<ConfigSnapshot>) -> Self {
        let version = tokio::sync::watch::Sender::new(initial.version);
        Self {
            snapshot: ArcSwap::new(initial),
            version,
        }
    }

    pub fn load(&self) -> Arc<ConfigSnapshot> {
        self.snapshot.load_full()
    }

    pub fn store(&self, snapshot: Arc<ConfigSnapshot>) {
        let version = snapshot.version;
        self.snapshot.store(snapshot);
        self.version.send_replace(version);
    }

    /// Watches the version of the latest stored snapshot. The value is updated after the snapshot is visible
    /// through [`Self::load`].
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<SnapshotVersion> {
        self.version.subscribe()
    }
}
