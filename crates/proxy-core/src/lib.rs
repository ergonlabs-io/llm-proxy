//! Runtime core: control/worker runtimes and config propagation (WP-06),
//! listener manager + filter-chain matching (WP-07), transport sockets (WP-08),
//! and the L4 network filter framework (WP-09).

pub mod drain;
pub mod filter_chain;
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
/// a `watch` ping for listener socket add/remove — WP-06).
///
/// In-flight connections keep their `Arc<ConfigSnapshot>` clone, which is what
/// gives Envoy-style drain semantics: old config lives exactly as long as the
/// connections created under it.
pub struct WorkerConfigHandle(ArcSwap<ConfigSnapshot>);

impl WorkerConfigHandle {
    pub fn new(initial: Arc<ConfigSnapshot>) -> Self {
        Self(ArcSwap::new(initial))
    }

    pub fn load(&self) -> Arc<ConfigSnapshot> {
        self.0.load_full()
    }

    pub fn store(&self, snapshot: Arc<ConfigSnapshot>) {
        self.0.store(snapshot);
    }
}
