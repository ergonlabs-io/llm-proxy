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

use std::sync::Arc;

use arc_swap::ArcSwap;
use proxy_config::ConfigSnapshot;

/// How each worker sees configuration. The control runtime builds immutable snapshots and `store`s them. Workers
/// `load` on connection accept, and react to a `watch` ping for listener socket add and remove. In-flight connections
/// keep their `Arc<ConfigSnapshot>`, which gives Envoy-style drain: old config lives as long as the connections made
/// under it.
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
pub struct WorkerConfigHandle(ArcSwap<ConfigSnapshot>);

impl WorkerConfigHandle {
    // Rust note: `pub(crate)` on purpose. A handle not enrolled in `runtime::SnapshotHandles` silently stops seeing
    // `publish()`. `SnapshotHandles::register` is the only place that both builds and enrolls, and the compiler refuses
    // the shortcut.
    pub(crate) fn new(initial: Arc<ConfigSnapshot>) -> Self {
        Self(ArcSwap::new(initial))
    }

    pub fn load(&self) -> Arc<ConfigSnapshot> {
        self.0.load_full()
    }

    pub fn store(&self, snapshot: Arc<ConfigSnapshot>) {
        self.0.store(snapshot);
    }
}
