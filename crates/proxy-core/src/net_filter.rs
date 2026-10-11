//! L4 network filter seam. Terminal filters (`tcp_proxy`, HCM) own the
//! upstream; config validation must reject chains whose last filter is not
//! terminal (matches Envoy).
//!
//! `tcp_proxy` (this WP, see `crate::tcp_proxy`) is the only L4 filter that
//! exists today, and it's terminal, so `listener.rs` dispatches to it
//! directly -- there's no chain-iteration engine here yet. `NetworkFilter`
//! stays as the declared seam for a future *non-terminal* L4 filter (e.g.
//! `proxy_protocol`), which would need to run ahead of the terminal filter and
//! hand off the (possibly mutated) stream to it.

use bytes::BytesMut;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetFilterStatus {
    Continue,
    StopIteration,
}

/// Read-path network filter, mirroring Envoy's `Network::ReadFilter`.
///
/// Rust note: no `Send` bound (ADR-0003) -- the worker-local data plane is
/// `!Send` by design (`spawn_local` on a single-threaded `LocalSet`), so a
/// `Send` bound here would make this trait unusable by any real filter impl
/// that closes over `Rc`/non-atomic state, same reasoning as every other
/// data-plane trait in this crate.
pub trait NetworkFilter {
    /// Called once when the connection is established (post transport-socket).
    fn on_new_connection(&mut self) -> NetFilterStatus {
        NetFilterStatus::Continue
    }

    /// Called with newly read data. Filters may consume/modify `data` in place.
    fn on_data(&mut self, data: &mut BytesMut, end_stream: bool) -> NetFilterStatus;
}
