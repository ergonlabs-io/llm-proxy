//! Per-stream bookkeeping shared by filters, the router, access logs, and stats.

use proxy_observability::records::Termination;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime};

use proxy_observability::access_log::{TimePoint, TimePoints};
use proxy_observability::trace::TraceContext;
use proxy_observability::ResponseFlag;

/// Provider-reported token usage. The four buckets remain separate because
/// cache reads and writes have different prices; input tokens exclude cached
/// tokens, so [`total`](Self::total) sums the buckets. This type stays here
/// because `proxy-filters` depends on `proxy-http`.
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

/// The immutable list-price observation for one completed request.
///
/// `LlmStats::list_cost` stays `None` when the provider reported no usage,
/// the request had no extracted model, or that `(provider type, model)` is
/// absent from the configured card.  This is intentionally distinct from
/// `Some(0)`: a zero price is a configured price, while `None` is unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmListCost {
    pub nanodollars: u64,
    /// `nanodollars` rounded up to micro-USD by the same function the spend
    /// filter charges with, so a request with no spend filter is entered in
    /// the ledger at the amount it would have been charged (ADR-0009
    /// decision 4).
    pub micro_usd: u64,
    pub rate_card_version: String,
}

/// What the spend filter added to the spend counters for this request,
/// published when it priced the request's usage so the ledger entry copies
/// the charge instead of pricing it a second time (ADR-0009 decision 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmSpendCharge {
    /// The charge; 0 when the rate card does not price the request.
    pub micro_usd: u64,
    /// The version of the card the spend filter priced with; `None` when it
    /// had no card.
    pub rate_card_version: Option<String>,
    /// The counters it was added to. Empty when no budget's credential scope
    /// matched the attempt (ADR-0007 decision 8).
    pub scopes: Vec<proxy_observability::records::ChargedScope>,
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

/// GenAI observations filled by the usage filter. Missing usage remains
/// `None`, never zero, because these values feed billing.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LlmStats {
    pub usage: Option<LlmTokenUsage>,
    /// Filled once, alongside final usage, after the response stream ends.
    pub list_cost: Option<LlmListCost>,
    /// Written by the spend filter when it charged this request; `None` when
    /// no spend filter ran or it saw no usage.
    pub spend_charge: Option<LlmSpendCharge>,
    /// The model the provider's response says it served (JSON `model`, or the
    /// first SSE frame that names one), bounded by the usage filter. Audit
    /// evidence, and the price key when the rate card lists it. `None` when the
    /// response named none.
    pub served_model: Option<String>,
    /// The provider's own id for this response (`chatcmpl-...`, `msg_...`,
    /// `resp_...`), bounded by the usage filter. Audit evidence for matching
    /// our record against the provider's dashboard.
    pub upstream_response_id: Option<String>,
    /// The provider's `usage` object exactly as sent (the last one, for a
    /// stream carrying several), as JSON text. Evidence only: nothing reads a
    /// field of it, and cost comes from the rate card alone.
    pub upstream_usage: Option<String>,
    /// Whether `usage` and `list_cost` describe a finished response.
    /// `Some(Partial)` is a stream cut off before the provider's final usage:
    /// the usage filter wrote an estimate (see `input_estimated` /
    /// `output_estimated`) so the request is still metered and charged.
    /// `None` means no usage filter ran.
    pub completeness: Option<proxy_observability::records::UsageCompleteness>,
    /// The input token count in `usage` is an estimate from the request body
    /// size, not a provider figure.
    pub input_estimated: bool,
    /// The output token count in `usage` is an estimate from the generated
    /// text that was streamed, not a provider figure.
    pub output_estimated: bool,
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
    /// stall. The full histogram is recorded by the GenAI TTFT/TPOT instruments.
    pub max_inter_chunk: Option<Duration>,
    /// Number of response body chunks observed. A streamed response that got
    /// coalesced into one chunk shows up here as `1` — which is exactly the
    /// streaming invariant failing, so it is worth counting.
    pub response_chunks: u64,
}

/// Authenticated caller identifiers from the auth filter. Policy is not
/// exposed through `StreamInfo`; consumers of security-sensitive identity
/// must treat `None` as unauthenticated and fail closed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AuthInfo {
    /// The tenant (account/team) the credential resolved to.
    pub tenant: Option<String>,
    /// WHICH credential authenticated — kept distinct from `tenant` because
    /// revoking one leaked key must not revoke the whole account, and an
    /// audit trail needs to name the key.
    pub key_id: Option<String>,
    /// The authenticated user (`Principal::user_id`): the virtual key's id,
    /// or a JWT's scoped subject. `None` when the credential names no user.
    /// Never read from the request body. Not a metric label: user ids are
    /// unbounded (AGENTS.md "Policy Domains").
    pub user_id: Option<String>,
    /// The control-plane `policy_generation` of the snapshot that verified
    /// the credential, so a request record names the policy it was admitted
    /// under. `None` when the authenticator does not read that snapshot (JWT)
    /// or the store's stamp could not be read.
    pub policy_generation: Option<u64>,
    /// The tenant's trace-export opt-in (ADR-0008 decision 2), pinned by the
    /// auth filter at admission. `false` (the default) captures nothing.
    pub trace_export: bool,
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
    /// The model the provider reported serving on this attempt, written by the
    /// usage filter onto the selected attempt only.
    pub served_model: Option<String>,
    /// The provider's response id on this attempt (selected attempt only),
    /// written by the usage filter. See [`LlmStats::upstream_response_id`].
    pub upstream_response_id: Option<String>,
    /// The provider's `usage` object as sent (selected attempt only). See
    /// [`LlmStats::upstream_usage`].
    pub upstream_usage: Option<String>,
    pub started_at: SystemTime,
    pub started_instant: Instant,
    pub finished_at: Option<SystemTime>,
    pub duration: Duration,
    pub status: Option<u16>,
    pub termination: Termination,
    pub retry_reason: Option<String>,
    pub bytes_request: Option<u64>,
    pub bytes_response: u64,
    /// Set by the router at the credential step; `None` if the attempt
    /// never got there.
    pub credential_source: Option<crate::tenant_credentials::CredentialSource>,
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

/// The upstream half of `%COMMON_DURATION%` for one physical attempt: the
/// `US_*` points. Each attempt gets its own, so a retry or a losing hedge
/// never writes into the timing of the attempt that produced the response;
/// [`StreamInfo::upstream_timing`] names the one the log reports.
///
/// Rust note: a `Cell` of a `Copy` value, not a `RefCell`, because the body
/// wrappers that stamp it are polled by hyper outside any `StreamInfo`
/// borrow, and a `Cell` can never fail a borrow check at runtime.
#[derive(Debug, Default)]
pub(crate) struct UpstreamTiming(Cell<TimePoints>);

impl UpstreamTiming {
    /// Record `point` as happening now, unless it already happened: each
    /// point marks the first time its condition held.
    pub(crate) fn mark(&self, point: TimePoint) {
        let mut points = self.0.get();
        if points.get(point).is_none() {
            points.set(point, Some(Instant::now()));
            self.0.set(points);
        }
    }

    /// Copy the connection's establishment points, as Envoy's router does in
    /// `onPoolReady`. A reused connection repeats the values from when it was
    /// dialed (Envoy v1.38 docs: they "repeat for all requests in a given
    /// connection").
    pub(crate) fn set_connect(&self, connect: proxy_cluster::ConnectTiming) {
        let mut points = self.0.get();
        points.set(TimePoint::UsCxBeg, connect.connect_start);
        points.set(TimePoint::UsCxEnd, connect.connect_end);
        points.set(TimePoint::UsHsEnd, connect.handshake_end);
        self.0.set(points);
    }

    pub(crate) fn points(&self) -> TimePoints {
        self.0.get()
    }
}

/// A request's trace-export capture while it runs (ADR-0008), with the
/// request facts the exporter needs. Lives on the stream so the filter
/// manager can admit it after the decode chain and `LoggingBody` can feed and
/// finish it.
#[derive(Debug)]
pub(crate) struct TraceTee {
    pub(crate) capture: proxy_observability::traces::capture::TraceCapture,
    pub(crate) path: String,
    pub(crate) request_content_type: Option<String>,
    pub(crate) request_content_encoding: Option<String>,
}

/// Per-request state consumed by access logging and stats.
#[derive(Debug)]
pub struct StreamInfo {
    pub downstream: Option<crate::handler::DownstreamInfo>,
    /// The client address limits and logs should attribute this request to.
    /// It is the TCP peer, except behind `xff_num_trusted_hops` trusted
    /// proxies on a non-edge HCM, where it is the `x-forwarded-for` entry
    /// those hops vouch for. With no trusted hops it is never read from
    /// `x-forwarded-for`, which the client itself can write.
    pub client_address: Option<std::net::IpAddr>,
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
    /// The upstream host dialed for this request's last (or only)
    /// attempt -- `%UPSTREAM_HOST%`. Set at the router's dial site, once a
    /// host is picked; `None` for a request that never reached an upstream
    /// (a local reply, or one that failed before host selection).
    pub upstream_host: Option<String>,
    /// The cluster the request was forwarded to -- `%UPSTREAM_CLUSTER%`.
    pub upstream_cluster: Option<String>,
    /// The usage dialect spoken by the selected upstream member. This is the
    /// provider actually dialled after any aggregate/fallback choice, so the
    /// usage filter can parse the response with the correct schema even when
    /// the route still carries a legacy compatibility override.
    pub upstream_usage_dialect: Option<proxy_config::ir::UsageDialect>,
    /// The HTTP version spoken to the upstream -- `%PROTOCOL%`.
    /// `None` for a local reply, which never dials one.
    pub protocol: Option<String>,
    /// Running byte count for `%BYTES_RECEIVED%`. Set from the
    /// already-buffered request body's length (ADR-0004 step 3: decode is
    /// always fully buffered before the terminal runs, so this is a plain
    /// assignment in `router::apply_forward`, never incremental).
    pub bytes_received: u64,
    /// Final byte count for `%BYTES_SENT%`, written by
    /// `access_logging::LoggingBody` once the response body ends (or is
    /// dropped mid-stream) -- see its doc for why that, not header-flush
    /// time, is the only correct moment for a streamed response.
    pub bytes_sent: u64,
    /// GenAI observations, written by the usage filter (`proxy-filters`)
    /// on the encode path. Left at `Default` for every non-LLM stream.
    pub llm: LlmStats,
    /// The authenticated caller, written by the auth filter
    /// (`proxy-filters`) on the decode path. Both fields stay `None` when no
    /// auth filter is configured — see [`AuthInfo`] for why that case must
    /// never be papered over with a default identity.
    pub auth: AuthInfo,
    /// The authenticated tenant's own provider credentials (ADR-0007), set by
    /// the auth filter from the snapshot it authenticated against. `None`
    /// means platform mode. The request keeps this `Arc` for its lifetime, so
    /// a credential change applies to the next request, not to in-flight ones.
    pub tenant_credentials: Option<std::sync::Arc<crate::tenant_credentials::TenantCredentialSet>>,
    /// Whose credential the most recent attempt was sent with. Kept here as
    /// well as on `AttemptInfo` because attempt snapshots exist only while
    /// metadata capture is on, and access logs need it regardless.
    pub credential_source: Option<crate::tenant_credentials::CredentialSource>,
    /// The request body's `model` field, published by
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
    /// Set by the body_rewrite filter when it is configured to force usage
    /// reporting for this request's dialect; read by the router, which
    /// enforces it against the whole buffered body.
    pub force_include_usage: bool,
    /// Set by the body_rewrite filter when the route caps output tokens; read
    /// by the router, which clamps or injects the request's output-token
    /// limit in the whole buffered body. `None` means no cap.
    pub max_output_tokens: Option<u32>,
    /// The model alias a resolver chose for a request whose `requested_model`
    /// is a resolver trigger such as `auto`, published by
    /// `proxy_filters::model_resolver_filter`. `None` when no resolver ran or
    /// the request named a concrete model. Routing, authorization, and
    /// pricing use [`StreamInfo::routing_model`]; `requested_model` keeps what
    /// the client sent, so usage records show both.
    pub resolved_model: Option<String>,
    /// Provider-owned model selected for the current upstream attempt.
    pub selected_model: Option<String>,
    pub attempts: Vec<Rc<RefCell<AttemptInfo>>>,
    pub metadata_enabled: bool,
    /// No ledger slot under `on_unavailable: reject` (ADR-0009 decision 5).
    /// Set at admission, before any filter; the router answers it with a
    /// local 503 only when it would dial, so a filter's own refusal wins.
    pub ledger_refusal: Option<proxy_observability::ledger::LedgerRefusal>,
    #[cfg(unix)]
    pub metadata_lease: Option<std::sync::Arc<proxy_observability::capture::CaptureLease>>,
    pub metadata_request_id: Option<String>,
    pub metadata_attempt_limit: u16,
    pub attempts_truncated: bool,
    pub physical_attempt_count: u64,
    pub selected_attempt: Option<Rc<RefCell<AttemptInfo>>>,
    /// This stream's SERVER span context, set by
    /// `filter_manager::FilterChainHandler::handle` right after `StreamInfo`
    /// is built -- `None` whenever tracing is off (`ConfigSnapshot::tracing`
    /// is `None`), regardless of whether an inbound request carried a
    /// `traceparent`. `router::RouterHandler` reads this to mint each
    /// attempt's CLIENT span as a [`TraceContext::child`] of it, so a
    /// retry/fallback stays under the same trace. See `TracingConfig`'s doc
    /// (`proxy-config`) for the sampling contract this field's `sampled` bit
    /// must satisfy.
    pub trace: Option<TraceContext>,
    /// S10: the downstream connection's pending HTTP
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
    /// The downstream `%COMMON_DURATION%` points other than `DS_RX_BEG`,
    /// which is [`Self::request_started_at`].
    pub(crate) downstream_timing: TimePoints,
    /// The upstream points of the attempt this request is logged against:
    /// the last one dispatched, or the hedge that won. `None` when no attempt
    /// was made.
    pub(crate) upstream_timing: Option<Rc<UpstreamTiming>>,
    /// Trace capture of an opted-in request; `None` otherwise.
    pub(crate) trace_tee: Option<TraceTee>,
}

impl Default for StreamInfo {
    fn default() -> Self {
        Self {
            request_started_at: Instant::now(),
            downstream: None,
            client_address: None,
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
            tenant_credentials: None,
            credential_source: None,
            requested_model: None,
            force_include_usage: false,
            max_output_tokens: None,
            resolved_model: None,
            selected_model: None,
            attempts: Vec::new(),
            metadata_enabled: false,
            ledger_refusal: None,
            #[cfg(unix)]
            metadata_lease: None,
            metadata_request_id: None,
            metadata_attempt_limit: proxy_observability::records::MAX_ATTEMPTS,
            attempts_truncated: false,
            physical_attempt_count: 0,
            selected_attempt: None,
            trace: None,
            on_upgrade: None,
            downstream_timing: TimePoints::default(),
            upstream_timing: None,
            trace_tee: None,
        }
    }
}

impl StreamInfo {
    /// The model this request is routed, authorized, and priced as: the
    /// resolver's choice when one ran, otherwise the client's own model.
    pub fn routing_model(&self) -> Option<&str> {
        self.resolved_model
            .as_deref()
            .or(self.requested_model.as_deref())
    }

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
            served_model: None,
            upstream_response_id: None,
            upstream_usage: None,
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
            credential_source: None,
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
            a.served_model = None;
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

    /// Record a downstream `%COMMON_DURATION%` point as happening now.
    pub(crate) fn mark_downstream(&mut self, point: TimePoint) {
        if self.downstream_timing.get(point).is_none() {
            self.downstream_timing.set(point, Some(Instant::now()));
        }
    }

    /// Every `%COMMON_DURATION%` point this request reached.
    pub(crate) fn time_points(&self) -> TimePoints {
        let mut points = self
            .upstream_timing
            .as_ref()
            .map(|timing| timing.points())
            .unwrap_or_default();
        points.set(TimePoint::DsRxBeg, Some(self.request_started_at));
        for point in [TimePoint::DsRxEnd, TimePoint::DsTxBeg, TimePoint::DsTxEnd] {
            points.set(point, self.downstream_timing.get(point));
        }
        points
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
