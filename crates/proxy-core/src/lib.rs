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

/// How each worker sees configuration. The control runtime builds immutable
/// snapshots and `store`s them; workers `load` on connection accept (and react to
/// a `watch` ping for listener socket add/remove).
///
/// In-flight connections keep their `Arc<ConfigSnapshot>` clone, which is what
/// gives Envoy-style drain semantics: old config lives exactly as long as the
/// connections created under it.
///
/// The only way to obtain one from outside this crate is
/// [`runtime::SnapshotHandles::register`], which enrolls it so
/// [`runtime::ConfigPublisher::publish`] can find it again -- a handle built
/// any other way would silently stop seeing config reloads (this is exactly
/// how the admin server's `/config_dump` went stale after a SIGHUP reload).
/// `WorkerConfigHandle::new` is `pub(crate)`, so this isn't just documented,
/// it doesn't compile:
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
    // Rust note: `pub(crate)` rather than `pub` on purpose. A handle that
    // isn't enrolled in `runtime::SnapshotHandles` is exactly the bug this
    // type exists to prevent -- it silently stops seeing `publish()`s (the
    // admin server's `/config_dump` did precisely this after a SIGHUP
    // reload). Keeping `new` crate-visible means `SnapshotHandles::register`
    // (the only place that both builds a handle and enrolls it) is the only
    // way anything outside `proxy-core` can obtain one; the compiler refuses
    // the shortcut instead of a doc comment merely discouraging it.
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
