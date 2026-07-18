//! Per-stream bookkeeping shared by filters, the router, access logs, and stats.

use proxy_observability::ResponseFlag;

/// Envoy's `StreamInfo`: populated throughout the request lifecycle, consumed by
/// access logging (WP-24) and stats (WP-23).
///
/// TODO(WP-11/WP-13): timing points (including TTFT/TPOT for Lane H), byte
/// counts, upstream host/cluster, attempt count, dynamic metadata, filter state.
#[derive(Debug, Default)]
pub struct StreamInfo {
    // Rust note: private field + public accessor methods below keep the
    // "no duplicate flags" invariant enforceable in one place.
    response_flags: Vec<ResponseFlag>,
    /// `%RESPONSE_CODE_DETAILS%` — set by whoever finalizes the response.
    pub response_code_details: Option<String>,
    pub is_local_reply: bool,
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
