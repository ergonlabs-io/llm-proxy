//! Per-stream bookkeeping shared by filters, the router, access logs, and stats.

use std::time::Duration;

use proxy_observability::ResponseFlag;

/// WP-33/34: tokens billed for one LLM request, as reported by the provider.
///
/// Four buckets, not two, and they are mirrored one-for-one from
/// `proxy_filters::usage::TokenUsage` — because the four are **priced
/// differently**. Cache-read tokens bill at a steep discount and cache-write
/// tokens at a premium, so a downstream consumer handed only
/// `input`/`output` cannot compute a correct cost. Collapsing them here would
/// make the token-budget limiter (WP-34) structurally unable to be right.
///
/// The buckets do not overlap — `input_tokens` is already net of the cached
/// portion — so [`total`](Self::total) is a plain sum.
///
/// Deliberately a plain data struct rather than a re-export of
/// `proxy_filters::usage::TokenUsage`: `proxy-filters` depends on
/// `proxy-http`, so the dependency cannot point the other way. The usage
/// filter converts at its boundary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LlmTokenUsage {
    /// Standard (non-cached) input tokens, at the base input rate.
    pub input_tokens: u64,
    /// Cache-**read** input tokens, served from a prompt cache at a discount.
    pub cached_tokens: u64,
    /// Cache-**write** input tokens, at a premium over base input. Always 0
    /// for providers with no such billed bucket (e.g. OpenAI).
    pub cache_creation_tokens: u64,
    /// Output/completion tokens.
    pub output_tokens: u64,
}

impl LlmTokenUsage {
    /// Total across all four buckets. Sound to sum because they don't overlap.
    pub fn total(&self) -> u64 {
        self.input_tokens
            .saturating_add(self.cached_tokens)
            .saturating_add(self.cache_creation_tokens)
            .saturating_add(self.output_tokens)
    }
}

/// WP-33: the GenAI observations for one stream, filled in by the usage filter
/// on the encode path.
///
/// `None` everywhere is the correct state for a non-LLM route, a request that
/// never reached an upstream, or a provider response that reported no usage —
/// per the WP-34 spec subtlety, *absent* usage must never be recorded as zero
/// tokens, because this number feeds billing.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LlmStats {
    pub usage: Option<LlmTokenUsage>,
    /// Time-to-first-token: response headers → first byte of response body.
    pub time_to_first_byte: Option<Duration>,
    /// Largest gap between two consecutive body chunks — the tail of the TPOT
    /// (time-per-output-token) distribution, which is what users feel as a
    /// stall. The full histogram lands with stats in WP-33b.
    pub max_inter_chunk: Option<Duration>,
    /// Number of response body chunks observed. A streamed response that got
    /// coalesced into one chunk shows up here as `1` — which is exactly the
    /// WP-33 streaming invariant failing, so it is worth counting.
    pub response_chunks: u64,
}

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
    /// WP-24: running byte count for `%BYTES_RECEIVED%`. Set from the
    /// already-buffered request body's length (ADR-0004 step 3: decode is
    /// always fully buffered before the terminal runs, so this is a plain
    /// assignment in `router::apply_forward`, never incremental).
    pub bytes_received: u64,
    /// WP-24: final byte count for `%BYTES_SENT%`, written by
    /// `access_logging::LoggingBody` once the response body ends (or is
    /// dropped mid-stream) -- see its doc for why that, not header-flush
    /// time, is the only correct moment for a streamed response.
    pub bytes_sent: u64,
    /// WP-33: GenAI observations, written by the usage filter (`proxy-filters`)
    /// on the encode path. Left at `Default` for every non-LLM stream.
    pub llm: LlmStats,
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
