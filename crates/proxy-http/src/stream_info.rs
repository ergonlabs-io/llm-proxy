//! Per-stream bookkeeping shared by filters, the router, access logs, and stats.

use std::time::{Duration, Instant};

use proxy_observability::trace::TraceContext;
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

/// The immutable list-price observation for one completed request (WP-53).
///
/// `LlmStats::list_cost` stays `None` when the provider reported no usage,
/// the request had no extracted model, or that `(provider type, model)` is
/// absent from the configured card.  This is intentionally distinct from
/// `Some(0)`: a zero price is a configured price, while `None` is unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmListCost {
    pub nanodollars: u64,
    pub rate_card_version: String,
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

/// The response wire system the usage filter identified for a stream.
///
/// This stays a small closed enum rather than a caller-provided string: it is
/// used as an OTel `gen_ai.system` attribute, so accepting arbitrary values
/// here would create a cardinality path from the request into metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenAiSystem {
    OpenAi,
    Anthropic,
}

impl GenAiSystem {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::Anthropic => "anthropic",
        }
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
    /// Filled once, alongside final usage, after the response stream ends.
    pub list_cost: Option<LlmListCost>,
    /// The response dialect selected from the route's usage-filter config.
    /// `None` means no usage filter ran, so GenAI latency metrics must not
    /// guess a system from a cluster name.
    pub system: Option<GenAiSystem>,
    /// Time-to-first-token: response headers → first byte of response body.
    pub time_to_first_byte: Option<Duration>,
    /// Time from the downstream request entering the filter chain to the
    /// first response-body byte. Unlike `time_to_first_byte`, this includes
    /// the upstream's time to headers and is the value OTel latency metrics
    /// need. It intentionally leaves the existing access-log TTFT meaning
    /// unchanged.
    pub time_to_first_body_byte: Option<Duration>,
    /// Largest gap between two consecutive body chunks — the tail of the TPOT
    /// (time-per-output-token) distribution, which is what users feel as a
    /// stall. The full histogram lands with stats in WP-33b.
    pub max_inter_chunk: Option<Duration>,
    /// Number of response body chunks observed. A streamed response that got
    /// coalesced into one chunk shows up here as `1` — which is exactly the
    /// WP-33 streaming invariant failing, so it is worth counting.
    pub response_chunks: u64,
}

/// WP-50: who the downstream caller was authenticated as, written by the auth
/// filter (`proxy-filters`) on the decode path.
///
/// # Why plain `String`s and not `proxy_filters::auth::Principal`
///
/// Same dependency direction as [`LlmTokenUsage`] above: `proxy-filters`
/// depends on `proxy-http`, so the richer type cannot travel the other way.
/// The auth filter converts at its boundary. What crosses is deliberately only
/// the two *identifiers* — a `Principal` also carries an `Arc<TenantPolicy>`,
/// and policy is not something a downstream consumer of `StreamInfo` (access
/// logs, stats) has any business reading.
///
/// # `None` means "not authenticated", and every reader must treat it as such
///
/// A stream where the auth filter is not configured, or that was refused
/// before authentication, leaves both fields `None`. **A consumer keying
/// anything security-relevant off `tenant` must fail closed on `None` rather
/// than substitute a default**, because the alternative — one shared implicit
/// bucket for every unauthenticated caller — is exactly the identity confusion
/// authentication exists to remove. See
/// `proxy_filters::token_limit_filter`'s bucket-key selection for the one
/// consumer that exists today and how it handles the absent case.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AuthInfo {
    /// The tenant (account/team) the credential resolved to.
    pub tenant: Option<String>,
    /// WHICH credential authenticated — kept distinct from `tenant` because
    /// revoking one leaked key must not revoke the whole account, and an
    /// audit trail needs to name the key.
    pub key_id: Option<String>,
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
#[derive(Debug)]
pub struct StreamInfo {
    /// Monotonic baseline established when this stream enters the HCM. Kept
    /// private to this crate; filters publish only derived durations so no
    /// cross-crate API can accidentally compare `Instant`s from unrelated
    /// streams.
    pub(crate) request_started_at: Instant,
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
    /// WP-50: the authenticated caller, written by the auth filter
    /// (`proxy-filters`) on the decode path. Both fields stay `None` when no
    /// auth filter is configured — see [`AuthInfo`] for why that case must
    /// never be papered over with a default identity.
    pub auth: AuthInfo,
    /// WP-50 increment 3a: the request body's `model` field, published by
    /// the body_rewrite filter (`proxy_filters::body_rewrite_filter`) on the
    /// decode path once it has scanned the body -- the same scan that filter
    /// already performs for its own `x-llmproxy-model` routing header, never
    /// a second body buffer. `None` until that filter has run, and also
    /// `None` for a request with no extractable model (no body, non-JSON
    /// content type, or the body's top-level object never named one within
    /// the scan window). `proxy_filters::model_authz_filter` reads this to
    /// authorize a request against a tenant's model allow-list, and fails
    /// closed on `None` -- see that filter's module doc.
    pub requested_model: Option<String>,
    /// WP-51 increment 2: this stream's SERVER span context, set by
    /// `filter_manager::FilterChainHandler::handle` right after `StreamInfo`
    /// is built -- `None` whenever tracing is off (`ConfigSnapshot::tracing`
    /// is `None`), regardless of whether an inbound request carried a
    /// `traceparent`. `router::RouterHandler` reads this to mint each
    /// attempt's CLIENT span as a [`TraceContext::child`] of it, so a
    /// retry/fallback stays under the same trace. See `TracingConfig`'s doc
    /// (`proxy-config`) for the sampling contract this field's `sampled` bit
    /// must satisfy.
    pub trace: Option<TraceContext>,
    /// S10 (WP-10 increment 2b/2c): the downstream connection's pending HTTP
    /// upgrade, moved here from `HttpRequestParts::on_upgrade` by
    /// `filter_manager::FilterChainHandler::handle` right after this
    /// `StreamInfo` is built -- see that call site's Rust note for why it
    /// has to happen there (before `req` moves into the filter chain) rather
    /// than wherever the request eventually reaches the router. `None` for a
    /// normal request. The router terminal reads this to decide whether to
    /// gate/tunnel an upgrade, and `.take()`s it once the upstream answers
    /// `101` -- pairing it with the upstream's own `OnUpgrade` into a
    /// `handler::UpgradeTunnel` that `codec::serve_one` bridges after the
    /// `101` response reaches hyper. Left unfulfilled (simply dropped) on
    /// every path that does NOT end in a tunnel, which is the correct signal
    /// to hyper that no upgrade happened.
    pub on_upgrade: Option<hyper::upgrade::OnUpgrade>,
}

impl Default for StreamInfo {
    fn default() -> Self {
        Self {
            request_started_at: Instant::now(),
            response_flags: Vec::new(),
            response_code_details: None,
            is_local_reply: false,
            upstream_host: None,
            upstream_cluster: None,
            protocol: None,
            bytes_received: 0,
            bytes_sent: 0,
            llm: LlmStats::default(),
            auth: AuthInfo::default(),
            requested_model: None,
            trace: None,
            on_upgrade: None,
        }
    }
}

impl StreamInfo {
    /// Returns `now - request_started_at` without exposing the raw monotonic
    /// instant outside `proxy-http`. Encode filters use this to publish an
    /// end-to-end first-body-byte duration for OTel metrics.
    pub fn elapsed_since_request_started(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.request_started_at)
    }

    pub fn set_response_flag(&mut self, flag: ResponseFlag) {
        if !self.response_flags.contains(&flag) {
            self.response_flags.push(flag);
        }
    }

    pub fn response_flags(&self) -> &[ResponseFlag] {
        &self.response_flags
    }
}
