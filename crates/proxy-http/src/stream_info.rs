//! Per-stream bookkeeping shared by filters, the router, access logs, and stats.

use proxy_observability::records::Termination;
use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime};

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

/// Physical upstream attempt snapshots. A new entry is created at dispatch,
/// not when the logical request is created, so retries and fallback members
/// remain visible independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptInfo {
    pub attempt_id: String,
    pub attempt_index: u16,
    /// Actual CLIENT span, when the router creates one.
    pub trace: Option<TraceContext>,
    /// SERVER context available even on paths without a CLIENT span.
    pub parent_trace: Option<TraceContext>,
    pub cluster: String,
    pub host: String,
    pub upstream_model: Option<String>,
    pub started_at: SystemTime,
    pub started_instant: Instant,
    pub finished_at: Option<SystemTime>,
    pub duration: Duration,
    pub status: Option<u16>,
    pub termination: Termination,
    pub retry_reason: Option<String>,
    pub bytes_request: Option<u64>,
    pub bytes_response: u64,
}

impl AttemptInfo {
    pub fn finish(&mut self, termination: Termination) {
        if self.finished_at.is_none() {
            self.finished_at = Some(SystemTime::now());
            self.duration = self.started_instant.elapsed();
            self.termination = termination;
        }
    }
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
    pub downstream: Option<crate::handler::DownstreamInfo>,
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
    /// The usage dialect spoken by the selected upstream member. This is the
    /// provider actually dialled after any aggregate/fallback choice, so the
    /// usage filter can parse the response with the correct schema even when
    /// the route still carries a legacy compatibility override.
    pub upstream_usage_dialect: Option<proxy_config::ir::UsageDialect>,
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
    /// Provider-owned model selected for the current upstream attempt.
    pub selected_model: Option<String>,
    pub attempts: Vec<Rc<RefCell<AttemptInfo>>>,
    pub metadata_enabled: bool,
    #[cfg(unix)]
    pub metadata_lease: Option<std::sync::Arc<proxy_observability::capture::CaptureLease>>,
    pub metadata_request_id: Option<String>,
    pub metadata_attempt_limit: u16,
    pub attempts_truncated: bool,
    pub physical_attempt_count: u64,
    pub selected_attempt: Option<Rc<RefCell<AttemptInfo>>>,
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
            downstream: None,
            response_flags: Vec::new(),
            response_code_details: None,
            is_local_reply: false,
            upstream_host: None,
            upstream_cluster: None,
            upstream_usage_dialect: None,
            protocol: None,
            bytes_received: 0,
            bytes_sent: 0,
            llm: LlmStats::default(),
            auth: AuthInfo::default(),
            requested_model: None,
            selected_model: None,
            attempts: Vec::new(),
            metadata_enabled: false,
            #[cfg(unix)]
            metadata_lease: None,
            metadata_request_id: None,
            metadata_attempt_limit: proxy_observability::records::MAX_ATTEMPTS,
            attempts_truncated: false,
            physical_attempt_count: 0,
            selected_attempt: None,
            trace: None,
            on_upgrade: None,
        }
    }
}

impl StreamInfo {
    pub fn begin_attempt(
        &mut self,
        cluster: &str,
        host: &str,
        upstream_model: Option<String>,
    ) -> Option<Rc<RefCell<AttemptInfo>>> {
        #[cfg(unix)]
        self.check_capture_gate();
        if !self.metadata_enabled {
            return None;
        }
        self.physical_attempt_count = self.physical_attempt_count.saturating_add(1);
        #[cfg(unix)]
        if self.metadata_lease.as_ref().is_some_and(|l| {
            4096usize.saturating_add((self.attempts.len() + 1) * 4096) > l.max_state_bytes()
        }) {
            self.attempts_truncated = true;
            return None;
        }
        if self.attempts.len()
            >= self
                .metadata_attempt_limit
                .min(proxy_observability::records::MAX_ATTEMPTS) as usize
        {
            self.attempts_truncated = true;
            return None;
        }
        let attempt_index = self.attempts.len().saturating_add(1).min(u16::MAX as usize) as u16;
        let attempt = Rc::new(RefCell::new(AttemptInfo {
            attempt_id: format!("attempt-{attempt_index}"),
            attempt_index,
            trace: None,
            parent_trace: self.trace,
            cluster: proxy_observability::records::bounded_field(cluster),
            host: proxy_observability::records::bounded_field(host),
            upstream_model: upstream_model.map(|m| proxy_observability::records::bounded_field(&m)),
            started_at: SystemTime::now(),
            started_instant: Instant::now(),
            finished_at: None,
            duration: Duration::ZERO,
            status: None,
            termination: Termination::Unknown,
            retry_reason: self.attempts.last().map(|previous| {
                if previous.borrow().cluster == cluster {
                    "retry"
                } else {
                    "fallback"
                }
                .to_owned()
            }),
            bytes_request: Some(0),
            bytes_response: 0,
        }));
        self.attempts.push(attempt.clone());
        Some(attempt)
    }

    #[cfg(unix)]
    pub(crate) fn check_capture_gate(&mut self) {
        if self.metadata_lease.as_ref().is_some_and(|l| !l.live()) {
            self.clear_capture_state();
        }
    }
    #[cfg(unix)]
    pub(crate) fn clear_capture_state(&mut self) {
        self.metadata_enabled = false;
        self.metadata_request_id = None;
        for attempt in &self.attempts {
            let Ok(mut a) = attempt.try_borrow_mut() else {
                return;
            };
            a.cluster = String::new();
            a.host = String::new();
            a.upstream_model = None;
            a.attempt_id = String::new();
            a.retry_reason = None;
        }
        self.selected_attempt = None;
        self.attempts = Vec::new();
        self.metadata_lease = None;
    }

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

#[cfg(test)]
mod metadata_tests {
    use super::*;
    #[test]
    fn capture_disabled_and_attempt_limit_do_not_retain_more_state() {
        let mut info = StreamInfo::default();
        assert!(info.begin_attempt("a", "host", None).is_none());
        assert!(info.attempts.is_empty());
        info.metadata_enabled = true;
        info.metadata_attempt_limit = 1;
        assert!(info.begin_attempt("a", "host", None).is_some());
        assert!(info.begin_attempt("b", "host", None).is_none());
        assert!(info.attempts_truncated);
        assert_eq!(info.attempts.len(), 1);
        assert_eq!(info.physical_attempt_count, 2);
    }
}

#[cfg(test)]
mod metadata_bounds_tests {
    use super::*;
    #[test]
    fn attempt_fields_and_limit_are_bounded_even_for_direct_callers() {
        let mut info = StreamInfo {
            metadata_enabled: true,
            metadata_attempt_limit: u16::MAX,
            ..Default::default()
        };
        let large = "é".repeat(2048);
        for _ in 0..65 {
            info.begin_attempt(&large, &large, Some(large.clone()));
        }
        assert_eq!(info.attempts.len(), 64);
        assert_eq!(info.physical_attempt_count, 65);
        assert!(info.attempts_truncated);
        let attempt = info.attempts[0].borrow();
        for field in [
            &attempt.cluster,
            &attempt.host,
            attempt.upstream_model.as_ref().unwrap(),
        ] {
            assert_eq!(field.len(), 512);
            assert!(field.capacity() <= 512);
        }
    }
}
