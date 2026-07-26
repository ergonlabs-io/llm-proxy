//! Per-stream bookkeeping shared by filters, the router, access logs, and stats.

use proxy_observability::ResponseFlag;

/// Envoy's `StreamInfo`: populated throughout the request lifecycle, consumed by
/// access logging (WP-24) and stats (WP-23).
///
/// TODO(WP-11/WP-13): TTFT/TPOT timing points for Lane H, attempt count,
/// dynamic metadata, filter state. Response flags, upstream host/cluster,
/// protocol, and byte counts are wired as of WP-24 chunk 3 -- see
/// `router::apply_forward` (flags, upstream host/cluster, protocol, at the
/// dial site) and `router::logging::LoggingBody` (`bytes_sent`, finalized at
/// stream end, not at header-flush time).
#[derive(Debug, Default)]
pub struct StreamInfo {
    // Rust note: private field + public accessor methods below keep the
    // "no duplicate flags" invariant enforceable in one place.
    response_flags: Vec<ResponseFlag>,
    /// `%RESPONSE_CODE_DETAILS%` — set by whoever finalizes the response.
    pub response_code_details: Option<String>,
    pub is_local_reply: bool,
    /// WP-24: the upstream host dialed for this request's last (or only)
    /// attempt -- `%UPSTREAM_HOST%`. Set at the router's dial site, once a
    /// host is picked; `None` for a request that never reached an upstream
    /// (a local reply, or one that failed before host selection).
    pub upstream_host: Option<String>,
    /// WP-24: the cluster the request was forwarded to -- `%UPSTREAM_CLUSTER%`.
    pub upstream_cluster: Option<String>,
    /// WP-24: the HTTP version spoken to the upstream -- `%PROTOCOL%`.
    /// `None` for a local reply, which never dials one.
    pub protocol: Option<String>,
    /// WP-24: running byte count for `%BYTES_RECEIVED%`. Set once the
    /// request body's length is known -- either up front (the buffered
    /// retry-replay path) or incrementally as it streams through to the
    /// upstream (`router::logging::CountingRequestBody`).
    pub bytes_received: u64,
    /// WP-24: final byte count for `%BYTES_SENT%`, written by
    /// `router::logging::LoggingBody` once the response body ends (or is
    /// dropped mid-stream) -- see its doc for why that, not header-flush
    /// time, is the only correct moment for a streamed response.
    pub bytes_sent: u64,
}

impl StreamInfo {
    pub fn set_response_flag(&mut self, flag: ResponseFlag) {
        if !self.response_flags.contains(&flag) {
            self.response_flags.push(flag);
        }
    }

    pub fn response_flags(&self) -> &[ResponseFlag] {
        &self.response_flags
    }
}
