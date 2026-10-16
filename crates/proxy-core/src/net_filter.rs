//! L4 network filter seam. Terminal filters (`tcp_proxy`, HCM) own the upstream, and config validation must reject a
//! chain whose last filter is not terminal (matches Envoy).
//!
//! `tcp_proxy` is the only L4 filter today, and it is terminal, so `listener.rs` dispatches to it directly. There is
//! no chain-iteration engine yet. `NetworkFilter` is the seam for a future non-terminal L4 filter (for example
//! `proxy_protocol`), which would run ahead of the terminal filter and hand it the possibly mutated stream.

use bytes::BytesMut;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetFilterStatus {
    Continue,
    StopIteration,
}

/// Read-path network filter, mirroring Envoy's `Network::ReadFilter`.
///
/// Rust note: no `Send` bound (ADR-0003). The worker-local data plane is `!Send` by design, so a `Send` bound would
/// exclude any filter that closes over `Rc` or non-atomic state.
pub trait NetworkFilter {
    /// Called once when the connection is established (post transport-socket).
    fn on_new_connection(&mut self) -> NetFilterStatus {
        NetFilterStatus::Continue
    }

    /// Called with newly read data. Filters may consume/modify `data` in place.
    fn on_data(&mut self, data: &mut BytesMut, end_stream: bool) -> NetFilterStatus;
}
