//! L4 network filter framework (WP-09). Terminal filters (`tcp_proxy`, HCM) own
//! the upstream; config validation must reject chains whose last filter is not
//! terminal (matches Envoy).

use bytes::BytesMut;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetFilterStatus {
    Continue,
    StopIteration,
}

/// Read-path network filter, mirroring Envoy's `Network::ReadFilter`.
pub trait NetworkFilter: Send {
    /// Called once when the connection is established (post transport-socket).
    fn on_new_connection(&mut self) -> NetFilterStatus {
        NetFilterStatus::Continue
    }

    /// Called with newly read data. Filters may consume/modify `data` in place.
    fn on_data(&mut self, data: &mut BytesMut, end_stream: bool) -> NetFilterStatus;
}
