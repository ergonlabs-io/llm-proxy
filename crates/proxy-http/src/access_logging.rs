//! Turns the parsed `AccessLogIR`/`FormatString`
//! (`proxy_observability::access_log`/`sink`) into real per-request log
//! lines. Originally lived under `router::logging` and was invoked from
//! `RouterHandler::handle_and_log` -- moved up to be a peer of
//! [`crate::filter_manager`] because the router sits INSIDE the encode
//! filter chain (`filter_manager::StreamingEncoder` wraps the router's
//! response body, not the other way around). Wrapping the response here,
//! from *inside* the router, meant [`LoggingBody`] rendered its line the
//! moment the router's own body hit end-of-stream -- which is BEFORE the
//! encode filter chain has had a chance to run its own end-of-stream
//! callback. An encode filter that records something at stream end (the
//! usage filter, notably) was therefore invisible to access logs.
//!
//! `FilterChainHandler::handle` now wraps the OUTERMOST response body --
//! i.e. `LoggingBody(StreamingEncoder(router's response))`, not
//! `StreamingEncoder(LoggingBody(router's response))` -- so a line is only
//! ever rendered once every encode filter (and the encode chain's own
//! end-of-stream flush) has already run. See `FilterChainHandler::handle`'s
//! own doc for exactly where that wrap happens and why it's the single
//! outermost exit point.
//!
//! Two pieces, unchanged from the original module:
//! - [`AccessLoggerRuntime`]: the resolved, per-HCM-bind runtime form of one
//!   `AccessLogIR` entry -- its sink already opened (or shared, via
//!   `SinkRegistry`, with any other logger in the same HCM pointed at the
//!   same file), so the hot per-request path here only ever renders +
//!   writes, no I/O setup.
//! - [`LoggingBody`]: the body combinator that actually calls those loggers,
//!   once, when a response is fully observed -- see its doc for why that has
//!   to be at *stream end*, not at header-flush time.

use std::cell::RefCell;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Instant, SystemTime};

use bytes::Bytes;
use http::HeaderMap;
use hyper::body::{Body, Frame};

use proxy_config::ir::{AccessLogFilterIR, AccessLogFormat, AccessLogIR, ComparisonOp};
use proxy_observability::access_log::{render, FormatString, LlmTokens, LogContext};
use proxy_observability::records::{
    RequestRecord, RequestRecordSink, MAX_PRINCIPAL_ID_BYTES, SCHEMA_VERSION,
};
use proxy_observability::sink::{AccessLogWriter, SinkRegistry};
use proxy_observability::trace::{FinishedSpan, SpanKind, SpanSink, SpanStatus};
use proxy_observability::ResponseFlag;

use crate::handler::{BodyError, StreamBody};
use crate::router::idle::IdleTimeoutError;
use crate::stat_handles::{GenAiLatencyStats, GenAiTokenStats};
use crate::stream_info::StreamInfo;
use crate::tenant_credentials::CredentialSource;

/// One configured logger, resolved at HCM-bind time (mirrors
/// `proxy-core::listener::build_listener_hcm`'s own "compiled once, rebuilt
/// only when the snapshot version changes" cadence -- a fresh
/// `FilterChainHandler`, and so a fresh set of these, is built on every
/// rebuild).
pub(crate) struct AccessLoggerRuntime {
    sink: std::sync::Arc<dyn AccessLogWriter>,
    format: AccessLogFormat,
    filter: Option<AccessLogFilterIR>,
}

impl AccessLoggerRuntime {
    /// Build the runtime loggers for one HCM's `access_logs`, in configured
    /// order, sharing sinks by destination via `registry` -- see
    /// `SinkRegistry`'s own doc for why that matters (two loggers naming the
    /// same file must not each open their own `BufWriter`, or their lines
    /// can interleave mid-write).
    pub(crate) fn build_all(
        access_logs: &[AccessLogIR],
        registry: &SinkRegistry,
    ) -> io::Result<Vec<AccessLoggerRuntime>> {
        access_logs
            .iter()
            .map(|log| {
                Ok(AccessLoggerRuntime {
                    sink: registry.build(&log.sink)?,
                    format: log.format.clone(),
                    filter: log.filter.clone(),
                })
            })
            .collect()
    }

    /// AGENTS.md invariant 1 note: every `AccessLogFilterIR` variant is matched
    /// explicitly here, same as `proxy_observability::sink::build_sink`
    /// matches every `AccessLogSink` variant -- a new filter kind is a
    /// compile error here, not a silent "always log" default.
    fn passes(&self, ctx: &LogContext<'_>) -> bool {
        match &self.filter {
            None => true,
            Some(AccessLogFilterIR::StatusCode { op, value }) => {
                let code = ctx.response_code.unwrap_or(0) as u32;
                match op {
                    ComparisonOp::Eq => code == *value,
                    ComparisonOp::Ge => code >= *value,
                    ComparisonOp::Le => code <= *value,
                    ComparisonOp::Ne => code != *value,
                }
            }
            // Envoy: an empty flag list means "log if *any* flag fired", not
            // "unconditionally pass" -- see `AccessLogFilterIR::ResponseFlag`'s
            // own doc in `proxy-config`.
            Some(AccessLogFilterIR::ResponseFlag(flags)) => {
                if flags.is_empty() {
                    !ctx.response_flags.is_empty()
                } else {
                    ctx.response_flags.iter().any(|f| flags.contains(f))
                }
            }
        }
    }

    fn render_line(&self, ctx: &LogContext<'_>) -> String {
        match &self.format {
            AccessLogFormat::Text(fmt) => render(fmt, ctx),
            AccessLogFormat::Json(fields) => render_json(fields, ctx),
        }
    }

    fn log(&self, ctx: &LogContext<'_>) {
        if !self.passes(ctx) {
            return;
        }
        // Non-blocking by contract: production sinks are `QueuedSink`s whose
        // writer thread batches and flushes, so no per-request flush here
        // (a flush would block this worker until the writer caught up).
        self.sink.write_line(&self.render_line(ctx));
    }
}

/// Render Envoy's `json_format`: every field's value is itself a rendered
/// [`FormatString`] (chunk 1), turned into a JSON string value. Envoy's real
/// `json_format` supports typed (numeric/bool/nested) values via shortcuts
/// this IR doesn't carry -- `AccessLogFormat::Json` is
/// `Vec<(String, FormatString)>`, always string-typed -- so every value
/// renders as a JSON string here, never a bare number/bool/object. That's a
/// known, disclosed gap (AGENTS.md invariant 1), not a silent one: nothing in the
/// IR asks for a typed value today, so there's nothing to drop.
fn render_json(fields: &[(String, FormatString)], ctx: &LogContext<'_>) -> String {
    let mut out = String::from("{");
    for (i, (key, fmt)) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        json_escape_into(key, &mut out);
        out.push_str("\":\"");
        json_escape_into(&render(fmt, ctx), &mut out);
        out.push('"');
    }
    out.push_str("}\n");
    out
}

fn json_escape_into(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
}

/// A snapshot of everything the access-log formatter needs from a request
/// head, taken at a point in time (see `ChainCtx::request_headers_snapshot`'s
/// doc in `filter_manager` for exactly when). Carries the four Envoy request
/// pseudo-headers alongside the header map -- rather than injecting them
/// into the map under some real header name -- because none of them are
/// legal `http::HeaderName`s (a colon isn't a valid HTTP field-name
/// character); `proxy_observability::access_log::LogContext`'s own
/// `request_method`/`request_path`/`request_authority`/`request_scheme`
/// fields exist for the same reason, and this struct is what feeds them.
///
/// Rust note: owns everything (`String`, not `&str`) rather than borrowing
/// from the request head -- the snapshot has to outlive the request head it
/// was taken from (it's read back after `FilterManager::run` returns, by
/// which point the head has already been consumed into the response path).
#[derive(Default)]
pub(crate) struct RequestSnapshot {
    pub(crate) headers: HeaderMap,
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) authority: Option<String>,
    pub(crate) scheme: Option<String>,
}

/// Build a [`RequestSnapshot`] from a request head. `authority` prefers the
/// URI's own `:authority` (`Uri::authority()` -- populated for absolute-form
/// requests, e.g. CONNECT or an HTTP/2 `:authority` pseudo-header threaded
/// through) and falls back to the `Host` header real origin-form requests
/// carry instead. `scheme` comes from the URI alone; an origin-form request
/// (the common case for a downstream HTTP/1 request line) carries no scheme,
/// so this is commonly `None` -- rendered as `-`, same as any other absent
/// pseudo-header.
///
/// Rust note: takes `&RequestHeaders` and clones its `HeaderMap` rather than
/// mutating in place -- every call site needs an independent snapshot (the
/// caller's own headers keep flowing through the rest of the pipeline
/// unmodified).
pub(crate) fn snapshot_request(head: &crate::filter::RequestHeaders) -> RequestSnapshot {
    let authority = head.uri.authority().map(|a| a.to_string()).or_else(|| {
        head.headers
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    });
    RequestSnapshot {
        headers: head.headers.clone(),
        method: head.method.to_string(),
        path: head.uri.path().to_string(),
        authority,
        scheme: head.uri.scheme_str().map(|s| s.to_string()),
    }
}

/// Maps the three GenAI request targets this proxy understands to OTel's
/// operation label. `responses` is deliberately the documented custom value
/// for OpenAI's Responses API: semconv v1.27 only standardizes `chat` and
/// `text_completion`, and calling Responses "chat" would be a false label.
fn gen_ai_operation(path: &str) -> Option<&'static str> {
    if path.ends_with("/chat/completions") || path.ends_with("/messages") {
        Some("chat")
    } else if path.ends_with("/completions") {
        Some("text_completion")
    } else if path.ends_with("/responses") {
        Some("responses")
    } else {
        None
    }
}

/// Everything [`LoggingBody`] needs to render + write a line once the
/// response stream ends (or is dropped mid-stream) -- assembled once, in
/// `FilterChainHandler::handle`, before the body starts streaming to the
/// downstream client.
pub(crate) struct AccessLogContext {
    pub(crate) loggers: Rc<Vec<AccessLoggerRuntime>>,
    pub(crate) stream_info: Rc<RefCell<StreamInfo>>,
    pub(crate) start_time: SystemTime,
    pub(crate) start_instant: Instant,
    pub(crate) request: RequestSnapshot,
    pub(crate) response_headers: HeaderMap,
    pub(crate) response_code: u16,
    pub(crate) downstream_remote_address: String,
    /// This stream's `llm.client.token.usage`
    /// recorder, if the HCM has one wired (`FilterChainHandler::with_token_stats`)
    /// -- `None` on any handler nothing attached one to (every pre-existing
    /// caller, and any HCM `proxy-core` never resolved provider handles
    /// for). See [`LoggingBody::finish`] for the one call site.
    pub(crate) token_stats: Option<Arc<GenAiTokenStats>>,
    /// OTel GenAI TTFT/TPOT recorder. Like token stats, it runs at stream end
    /// even when no access log destination is configured.
    pub(crate) latency_stats: Option<Arc<GenAiLatencyStats>>,
    /// This stream's span sink, if the HCM has one wired
    /// (`FilterChainHandler::with_tracing`) -- `None` on any handler tracing
    /// is off for. [`LoggingBody::finish`] emits the SERVER span through
    /// this, using `stream_info.trace` (set at stream start, `None` when
    /// this is also `None`) as its context.
    pub(crate) span_sink: Option<SpanSink>,
    /// Optional end-user metadata sink. Submission is a single nonblocking
    /// try-send at terminal completion; capture loss never changes the reply.
    pub(crate) request_record_sink: Option<Arc<dyn RequestRecordSink>>,
}

/// Wraps a response [`StreamBody`] so that -- regardless of whether the
/// stream completes normally, errors, or is simply dropped mid-flight (a
/// disconnecting client, or an outer combinator like `GuardedBody`/
/// `IdleTimeoutBody` giving up on it) -- exactly one access-log line is
/// rendered and written per configured logger, using the *final* byte count
/// and a duration covering the whole stream.
///
/// This is the seam access logging needs: logging when *response
/// headers* are produced (the naive place to hook) is wrong for every
/// streamed LLM response -- the body (the actual tokens) is what takes the
/// time and carries the bytes; headers arrive almost immediately. Wrapping
/// the body itself, the same way `GuardedBody`/`IdleTimeoutBody` already do
/// for the S5/S4 concerns, is what lets this observe the real end of the
/// stream.
///
/// **Deliberately observe-only: never inject into the stream.** When a
/// response fails mid-flight this records a `ResponseFlag` and warns, and
/// the downstream client simply sees the stream end (an unclean EOF, which
/// is what tells it the response was truncated). It is tempting to instead
/// synthesize an SSE error event so the client learns *why* -- do not. This
/// is a transparent proxy: response bytes reach the client exactly as the
/// provider produced them. A synthetic frame would have to be forged in the
/// provider's own event schema (OpenAI's and Anthropic's differ), so a
/// client would either fail to parse it or, far worse, mistake it for
/// something the model actually said. Failure attribution belongs in the
/// access log and the operator-facing warning, not in the response body.
/// (Owner decision, 2026-08-01.)
///
/// `LoggingBody` wraps the OUTERMOST response body -- see
/// `FilterChainHandler::handle`'s doc -- specifically OUTSIDE
/// `filter_manager::StreamingEncoder`, not nested inside the router's own
/// response like the pre-relocation design had it. That ordering is the
/// entire point of this module living here rather than under `router`: a
/// `StreamingEncoder(LoggingBody(...))` nesting renders the log line the
/// moment the router's body ends, before the encode filter chain's own
/// end-of-stream callback has run, which makes anything an encode filter
/// records at stream end (e.g. the usage filter's token counts)
/// invisible to the log. `LoggingBody(StreamingEncoder(...))` fixes that by
/// only ever observing end-of-stream *after* the whole encode chain -- and
/// its own end-of-stream flush -- has already run.
///
/// Rust note: `ctx` is `Option<AccessLogContext>` purely so `finish` can be
/// called from either `poll_frame` (the common case: the stream ends or
/// errors while still being polled) or `Drop` (the stream is abandoned
/// without ever being polled to completion) and only actually log once,
/// without a separate "have I already logged" bool.
pub(crate) struct LoggingBody {
    inner: StreamBody,
    bytes_sent: u64,
    trailers: HeaderMap,
    ctx: Option<AccessLogContext>,
    /// Bytes remaining per the response's own `content-length` header (the
    /// one actually going to the downstream client), decremented as each
    /// data frame is delivered. `None` means either there was no
    /// `content-length` header, or the running total has already overshot it
    /// (a filter mutated the body after headers were forwarded, so the
    /// header is stale) -- either way that's a permanent fallback to the
    /// ordinary post-`None` end-of-stream path below. See
    /// [`Self::note_frame_len`] for why this field exists at all: without
    /// it, a `content-length`-framed response was misclassified `DC` on
    /// every single request.
    remaining_content_length: Option<u64>,
}

impl LoggingBody {
    pub(crate) fn new(inner: StreamBody, ctx: AccessLogContext) -> Self {
        let remaining_content_length =
            crate::filter_manager::parse_content_length(&ctx.response_headers);
        Self {
            inner,
            bytes_sent: 0,
            trailers: HeaderMap::new(),
            ctx: Some(ctx),
            remaining_content_length,
        }
    }

    /// Count `len` bytes of a just-arrived data frame against
    /// [`Self::remaining_content_length`], returning `true` exactly when
    /// this frame is the one that exhausts it. Mirrors
    /// `filter_manager::StreamingEncoder::note_frame_len` and exists for the
    /// identical reason, one layer further out: hyper's HTTP/1 write
    /// dispatcher stops polling the response body the moment it has written
    /// exactly `content-length` bytes, so `poll_frame` never gets the
    /// terminal `None` this body's clean-end path (below) waits for.
    /// `StreamingEncoder`'s own version of this fix (already in
    /// place) solves that problem for the ENCODE FILTER CHAIN -- it makes
    /// sure an encode filter's end-of-stream logic (e.g. the usage
    /// filter's token-usage write) still runs. It does nothing for
    /// `LoggingBody`, which wraps `StreamingEncoder` from the OUTSIDE and is
    /// what hyper's write dispatcher actually holds: without this, a
    /// `content-length`-framed response (every non-streaming LLM reply)
    /// never observed its own clean end, `Drop` fired instead, and a fully
    /// successful `200` was logged `response_flags: DC` -- as if the
    /// downstream client had disconnected mid-response, when in fact every
    /// byte had already reached it.
    fn note_frame_len(&mut self, len: usize) -> bool {
        match self.remaining_content_length {
            Some(remaining) => match remaining.checked_sub(len as u64) {
                Some(0) => {
                    self.remaining_content_length = Some(0);
                    true
                }
                Some(new_remaining) => {
                    self.remaining_content_length = Some(new_remaining);
                    false
                }
                None => {
                    // Overshoot: the running total no longer agrees with the
                    // declared header, so the header was stale before we got
                    // here. Not ours to fix -- fall back to the ordinary
                    // post-`None` flush for the rest of the stream.
                    self.remaining_content_length = None;
                    false
                }
            },
            None => false,
        }
    }

    /// Classifies a body-stream failure into the `ResponseFlag` an operator
    /// needs to tell the three shapes apart: the client went away
    /// (`BodyError::Downstream` -> DC), the upstream connection died mid-body
    /// (`BodyError::Upstream` -> UC), or the upstream just went quiet past
    /// the S4 idle deadline while still (as far as we know) alive (`SI`).
    ///
    /// Rust note: `BodyError::Upstream`'s source is a type-erased
    /// `Box<dyn Error + Send + Sync>` (`router::idle::IdleTimeoutBody` and
    /// every other upstream body wrapper share that one variant), so the
    /// idle-timeout case can't be told apart by matching the `BodyError`
    /// variant alone -- `downcast_ref` walks the erased box back to its
    /// concrete type at runtime (this is exactly what `std::error::Error`'s
    /// inherited `Any`-based downcast exists for).
    fn classify(err: &BodyError) -> ResponseFlag {
        match err {
            BodyError::Downstream(_) => ResponseFlag::DownstreamConnectionTermination,
            BodyError::Upstream(source) => {
                if source.downcast_ref::<IdleTimeoutError>().is_some() {
                    ResponseFlag::StreamIdleTimeout
                } else {
                    ResponseFlag::UpstreamConnectionTermination
                }
            }
        }
    }

    /// Records a mid-stream failure (a `poll_frame` error, or a `Drop`
    /// before end-of-stream) onto `StreamInfo` and emits the operator-facing
    /// warning -- both before `finish()` snapshots the flags into the
    /// rendered line, since `finish()` (via `ctx.take()`) is the point of no
    /// return for this stream's log line. A no-op if `finish()` already ran
    /// (`self.ctx` is `None`): `poll_frame` and `Drop` both call this, and
    /// only the first to observe the failure should record it.
    fn record_failure(&mut self, flag: ResponseFlag, detail: &dyn std::fmt::Display) {
        let Some(ctx) = self.ctx.as_ref() else {
            return;
        };
        let (cluster, upstream_host, ttft) = {
            let mut info = ctx.stream_info.borrow_mut();
            info.set_response_flag(flag);
            (
                info.upstream_cluster.clone(),
                info.upstream_host.clone(),
                info.llm.time_to_first_byte,
            )
        };
        tracing::warn!(
            response_flag = flag.code(),
            cluster = cluster.as_deref().unwrap_or("-"),
            upstream_host = upstream_host.as_deref().unwrap_or("-"),
            bytes_sent = self.bytes_sent,
            elapsed_ms = ctx.start_instant.elapsed().as_millis() as u64,
            ttft_ms = ttft.map(|d| d.as_millis() as u64),
            error = %detail,
            "response stream failed mid-flight"
        );
    }

    fn finish(&mut self) {
        let Some(ctx) = self.ctx.take() else {
            // Already logged (`poll_frame` beat `Drop` to it, or vice versa).
            return;
        };
        let stream_duration = ctx.start_instant.elapsed();
        #[cfg(unix)]
        ctx.stream_info.borrow_mut().check_capture_gate();
        #[cfg(unix)]
        let lease = ctx.stream_info.borrow().metadata_lease.clone();
        #[cfg(unix)]
        let terminal = lease.as_ref().map(|l| l.reserve_terminal());
        #[cfg(unix)]
        let capture_allowed = (ctx.stream_info.borrow().metadata_enabled
            || ctx
                .request_record_sink
                .as_ref()
                .is_some_and(|s| !s.requires_admission()))
            && terminal.as_ref().is_none_or(|r| r.is_ok());
        #[cfg(not(unix))]
        let capture_allowed = ctx.stream_info.borrow().metadata_enabled;

        // Rust note: `stream_info`'s snapshot has to be pulled out of the
        // `RefCell` and its borrow dropped before `LogContext` is built --
        // `LogContext` only borrows the pieces it's handed, and holding the
        // `Ref` across that would just add a lifetime knot for no benefit
        // (nothing else touches `stream_info` concurrently by this point).
        let (
            response_flags,
            upstream_host,
            upstream_cluster,
            protocol,
            bytes_received,
            llm_tokens,
            llm_ttft,
            llm_max_stall,
            llm_response_chunks,
            llm_list_cost_nanodollars,
            llm_system,
            llm_time_to_first_body_byte,
            requested_model,
            llm_served_model,
            trace,
            tenant,
            response_code_details,
            usage_attribution,
            attempts,
        ) = {
            let mut info = ctx.stream_info.borrow_mut();
            info.bytes_sent = self.bytes_sent;
            if let Some(attempt) = &info.selected_attempt {
                attempt.borrow_mut().finish(metadata_termination(
                    info.response_flags(),
                    ctx.response_code,
                    info.is_local_reply,
                ));
            }
            // `LlmTokenUsage` -> `LlmTokens` field-for-field --
            // `proxy-observability` can't name `proxy_http::LlmTokenUsage`
            // (crate layering runs the other way), so this is the boundary
            // conversion; note this is a `Option<LlmTokenUsage>`, not a
            // struct with zeroed fields, so "no usage reported" stays `None`
            // all the way through to `render` (`-`, never `0`).
            let llm_tokens = info.llm.usage.map(|u| LlmTokens {
                input: u.input_tokens,
                cached: u.cached_tokens,
                cache_creation: u.cache_creation_tokens,
                output: u.output_tokens,
            });
            (
                info.response_flags().to_vec(),
                info.upstream_host.clone(),
                info.upstream_cluster.clone(),
                info.protocol.clone(),
                info.bytes_received,
                llm_tokens,
                info.llm.time_to_first_byte,
                info.llm.max_inter_chunk,
                info.llm.response_chunks,
                info.llm.list_cost.as_ref().map(|cost| cost.nanodollars),
                info.llm.system,
                info.llm.time_to_first_body_byte,
                info.requested_model.clone(),
                info.llm.served_model.clone(),
                info.trace,
                // The SAME `AuthInfo::tenant` the auth filter wrote,
                // read here rather than re-borrowing `stream_info` a second
                // time below -- see this destructuring's own doc above.
                info.auth.tenant.clone(),
                // `%RESPONSE_CODE_DETAILS%` -- cloned out alongside
                // everything else `LogContext` borrows, same reasoning as
                // this destructure's own doc above.
                info.response_code_details.clone(),
                (
                    info.auth.key_id.clone(),
                    info.selected_model.clone(),
                    info.resolved_model.clone(),
                    info.llm
                        .list_cost
                        .as_ref()
                        .map(|cost| cost.rate_card_version.clone()),
                ),
                (if capture_allowed {
                    info.attempts
                        .iter()
                        .map(|a| a.borrow().clone())
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                }),
            )
        };

        if let Some(sink) = ctx.request_record_sink.as_ref().filter(|_| capture_allowed) {
            // Request records never use the caller's x-request-id as their
            // identity. Internal identity is pinned at request admission.
            let request_id = ctx
                .stream_info
                .borrow()
                .metadata_request_id
                .clone()
                .unwrap_or_else(|| {
                    hex_bytes(&proxy_observability::trace::TraceContext::new_root(false).trace_id)
                });
            let termination = metadata_termination(
                &response_flags,
                ctx.response_code,
                ctx.stream_info.borrow().is_local_reply,
            );
            let mut record = RequestRecord {
                schema_version: SCHEMA_VERSION,
                event_id: format!("{}:terminal", request_id),
                request_id: request_id.clone(),
                instance_id: "proxy".to_owned(),
                started_at: format_system_time(ctx.start_time),
                finished_at: format_system_time(SystemTime::now()),
                tenant_id: tenant
                    .as_deref()
                    .map(proxy_observability::records::bounded_field)
                    .unwrap_or_else(|| "default".to_owned()),
                // AuthInfo deliberately exposes tenant and credential only.
                // A body-supplied user_id is untrusted, so leave this null
                // until authentication publishes an authenticated principal.
                user_id: None,
                key_id: usage_attribution
                    .0
                    .as_deref()
                    .map(proxy_observability::records::bounded_field),
                trace_id: trace.map(|t| hex_bytes(&t.trace_id)),
                // Integration owner: pin routing, authenticated policy, and capture
                // snapshot versions in StreamInfo at FilterChainHandler::handle
                // admission. Do not read current versions at terminal emission.
                routing_revision: None,
                policy_generation: None,
                capture_policy_version: {
                    #[cfg(unix)]
                    {
                        lease.as_ref().map(|l| l.version().to_owned())
                    }
                    #[cfg(not(unix))]
                    {
                        None
                    }
                },
                method: proxy_observability::records::bounded_field(&ctx.request.method),
                route: proxy_observability::records::bounded_field(&ctx.request.path),
                requested_model: requested_model
                    .as_deref()
                    .map(proxy_observability::records::bounded_field),
                resolved_model: usage_attribution
                    .2
                    .as_deref()
                    .map(proxy_observability::records::bounded_field),
                selected_cluster: upstream_cluster
                    .as_deref()
                    .map(proxy_observability::records::bounded_field),
                // Usage dialect is not provider identity. The trusted pricing
                // cluster-to-provider map currently lives privately in proxy-filters.
                selected_provider: None,
                selected_model: usage_attribution
                    .1
                    .as_deref()
                    .map(proxy_observability::records::bounded_field),
                status: Some(ctx.response_code),
                termination,
                error_category: response_code_details
                    .as_deref()
                    .map(proxy_observability::records::bounded_field),
                response_flags: response_flags
                    .iter()
                    .map(|flag| flag.code().to_owned())
                    .collect(),
                duration_ms: stream_duration.as_millis().min(u64::MAX as u128) as u64,
                time_to_first_byte_ms: llm_time_to_first_body_byte
                    .map(|d| d.as_millis().min(u64::MAX as u128) as u64),
                bytes_request: bytes_received,
                bytes_response: self.bytes_sent,
                usage: llm_tokens.map(|t| proxy_observability::records::Usage {
                    input_tokens: t.input,
                    cache_read_tokens: t.cached,
                    cache_write_tokens: t.cache_creation,
                    output_tokens: t.output,
                    completeness: proxy_observability::records::UsageCompleteness::Complete,
                    provenance: "provider".to_owned(),
                }),
                // A numeric amount without its immutable rate-card version
                // is not an auditable cost. Keep the whole cost null rather
                // than inventing an "unknown" version.
                cost: llm_list_cost_nanodollars
                    .zip(usage_attribution.3.as_deref())
                    .map(
                        |(amount, rate_card_version)| proxy_observability::records::Cost {
                            amount,
                            unit: "nanodollars".to_owned(),
                            currency: "USD".to_owned(),
                            rate_card_version: rate_card_version.to_owned(),
                            kind: "list".to_owned(),
                        },
                    ),
                attempt_count: attempts.len().min(u16::MAX as usize) as u16,
                physical_attempt_count: ctx.stream_info.borrow().physical_attempt_count,
                attempts_truncated: ctx.stream_info.borrow().attempts_truncated,
                // The router overwrites this on every attempt, so it holds the
                // final (selected) attempt's source.
                credential_source: ctx.stream_info.borrow().credential_source,
                attempts: attempts
                    .into_iter()
                    .map(|attempt| proxy_observability::records::AttemptRecord {
                        schema_version: SCHEMA_VERSION,
                        event_id: format!("{}:attempt:{}", request_id, attempt.attempt_index),
                        request_id: request_id.clone(),
                        attempt_id: format!("{}:{}", request_id, attempt.attempt_id),
                        attempt_index: attempt.attempt_index,
                        trace_id: attempt
                            .trace
                            .or(attempt.parent_trace)
                            .map(|t| hex_bytes(&t.trace_id)),
                        span_id: attempt.trace.map(|t| hex_bytes(&t.span_id)),
                        parent_span_id: attempt.parent_trace.map(|t| hex_bytes(&t.span_id)),
                        cluster: Some(attempt.cluster.clone()),
                        provider: None,
                        upstream_model: attempt.upstream_model,
                        served_model: attempt.served_model,
                        started_at: format_system_time(attempt.started_at),
                        finished_at: format_system_time(
                            attempt.finished_at.unwrap_or_else(SystemTime::now),
                        ),
                        duration_ms: attempt.duration.as_millis().min(u64::MAX as u128) as u64,
                        status: attempt.status,
                        termination: attempt.termination,
                        retry_reason: attempt.retry_reason,
                        bytes_request: attempt.bytes_request,
                        bytes_response: attempt.bytes_response,
                        usage: None,
                        cost: None,
                        credential_source: attempt.credential_source,
                    })
                    .collect(),
            };
            if let Some(selected) = ctx.stream_info.borrow().selected_attempt.as_ref() {
                let index = selected.borrow().attempt_index;
                if let Some(attempt) = record
                    .attempts
                    .iter_mut()
                    .find(|a| a.attempt_index == index)
                {
                    attempt.usage = record.usage.clone();
                    attempt.cost = record.cost.clone();
                    if attempt.termination == proxy_observability::records::Termination::Unknown {
                        attempt.termination = termination;
                    }
                    if termination == proxy_observability::records::Termination::Timeout {
                        attempt.termination = termination;
                    }
                }
            }
            // No validity pre-check here: a malformed record must reach the
            // sink (or capture permit) so it is counted as `invalid` in
            // `llmproxy_metadata_admission` rather than vanishing. Dropping the
            // permit on that path releases its reservation.
            #[cfg(unix)]
            if let Some(Ok(permit)) = terminal {
                // Trusted ownership identifiers are rejected, never truncated into collisions.
                if tenant
                    .as_ref()
                    .is_none_or(|t| t.len() <= MAX_PRINCIPAL_ID_BYTES)
                    && usage_attribution
                        .0
                        .as_ref()
                        .is_none_or(|k| k.len() <= MAX_PRINCIPAL_ID_BYTES)
                {
                    let _ = permit.submit(record);
                } else if let Some(lease) = &lease {
                    lease.identity_limit();
                }
            } else {
                let _ = sink.submit(record);
            }
            #[cfg(not(unix))]
            let _ = sink.submit(record);
        }

        #[cfg(unix)]
        if lease.is_some() {
            ctx.stream_info.borrow_mut().clear_capture_state();
        }

        // Record LLM_CLIENT_TOKEN_USAGE here, at the
        // same "stream has ended, exactly once" point access logging itself
        // uses. `provider` is the cluster ACTUALLY DIALLED
        // (`upstream_cluster`), never the routed cluster name -- AGENTS.md
        // invariant 6: on a fallback the two differ, and the member that served the
        // request is the one whose tokens these are. A stream with no usage
        // reported (`llm_tokens: None`) records nothing at all -- "no usage
        // was reported" and "zero tokens were used" are different facts, and
        // recording a zero here would silently corrupt any rate computed
        // from this series. `tenant` is `StreamInfo::auth.tenant` verbatim
        // -- `None` (no authenticated caller) still records, under
        // `GenAiTokenStats::record_usage`'s no-tenant sentinel; see that
        // method's doc for why unauthenticated usage is a naming decision,
        // not a skip.
        if let (Some(tokens), Some(token_stats), Some(provider)) = (
            llm_tokens,
            ctx.token_stats.as_ref(),
            upstream_cluster.as_deref(),
        ) {
            token_stats.record_usage(provider, tenant.as_deref(), tokens);
        }

        // Semconv v1.27's latency metrics require an operation, requested
        // model, and GenAI system. Each comes from a trustworthy local source:
        // operation from the request target, model from the body-rewrite
        // filter's parsed `requested_model` (never a cluster-name substitute),
        // and system from the route-selected usage filter. Missing any one is
        // an honest absence, not a reason to invent a label. Failed/truncated
        // responses are excluded because both semconv metrics are for
        // successful responses.
        if response_flags.is_empty() && (200..300).contains(&ctx.response_code) {
            if let (Some(latency_stats), Some(operation), Some(model), Some(system)) = (
                ctx.latency_stats.as_ref(),
                gen_ai_operation(&ctx.request.path),
                requested_model.as_deref(),
                llm_system,
            ) {
                latency_stats.record(
                    operation,
                    model,
                    system.as_str(),
                    llm_time_to_first_body_byte,
                    stream_duration,
                    llm_tokens.map(|tokens| tokens.output),
                );
            }
        }

        // Emit the SERVER span here -- the same
        // "stream has ended, exactly once" point the two instruments above
        // use. `trace` is `None` whenever tracing is off; `span_ctx.sampled`
        // is `false` for an unsampled root this stream's own head-sampling
        // decided against (an inbound `traceparent` that arrived sampled is
        // always honored -- see `FilterChainHandler::handle`'s join logic --
        // so this check is really "was this stream's trace ever going to be
        // recorded", not a second sampling decision).
        if let (Some(sink), Some(span_ctx)) = (ctx.span_sink.as_ref(), trace) {
            if span_ctx.sampled {
                let mut attributes = vec![
                    ("http.request.method", ctx.request.method.clone()),
                    ("http.route", ctx.request.path.clone()),
                    (
                        "response_flags",
                        proxy_observability::flags::render_flags(&response_flags),
                    ),
                ];
                if let Some(cluster) = upstream_cluster.as_deref() {
                    attributes.push(("upstream.cluster", cluster.to_string()));
                }
                if let Some(request_id) = ctx
                    .request
                    .headers
                    .get("x-request-id")
                    .and_then(|v| v.to_str().ok())
                {
                    attributes.push(("x-request-id", request_id.to_string()));
                }
                sink.emit(FinishedSpan {
                    context: span_ctx,
                    name: format!("{} {}", ctx.request.method, ctx.request.path),
                    kind: SpanKind::Server,
                    start: ctx.start_time,
                    end: SystemTime::now(),
                    attributes,
                    status: if ctx.response_code >= 500 {
                        SpanStatus::Error
                    } else {
                        SpanStatus::Ok
                    },
                });
            }
        }

        // A stats-only stream (token_stats wired, no access loggers) has
        // nothing left to do -- `LogContext` borrows a dozen fields purely to
        // hand them to `render`, so building it for an empty loop is waste on
        // every request of such a listener.
        if ctx.loggers.is_empty() {
            return;
        }

        let log_ctx = LogContext {
            start_time: ctx.start_time,
            request_headers: &ctx.request.headers,
            response_headers: &ctx.response_headers,
            response_trailers: &self.trailers,
            protocol: protocol.as_deref(),
            response_code: Some(ctx.response_code),
            response_flags: &response_flags,
            duration: Some(stream_duration),
            bytes_received,
            bytes_sent: self.bytes_sent,
            upstream_host: upstream_host.as_deref(),
            upstream_cluster: upstream_cluster.as_deref(),
            downstream_remote_address: Some(&ctx.downstream_remote_address),
            response_code_details: response_code_details.as_deref(),
            llm_tokens,
            llm_ttft,
            llm_max_stall,
            llm_response_chunks,
            llm_list_cost_nanodollars,
            llm_key_id: usage_attribution.0.as_deref(),
            llm_tenant: tenant.as_deref(),
            // `CredentialSource::as_str` is `&'static str`, so this borrow
            // needs no `Ref` kept alive past this struct literal.
            llm_credential_source: ctx
                .stream_info
                .borrow()
                .credential_source
                .map(CredentialSource::as_str),
            llm_user_id: None,
            llm_requested_model: requested_model.as_deref(),
            llm_resolved_model: usage_attribution.2.as_deref(),
            llm_selected_model: usage_attribution.1.as_deref(),
            llm_served_model: llm_served_model.as_deref(),
            llm_rate_card_version: usage_attribution.3.as_deref(),
            request_method: Some(&ctx.request.method),
            request_path: Some(&ctx.request.path),
            request_authority: ctx.request.authority.as_deref(),
            request_scheme: ctx.request.scheme.as_deref(),
        };
        for logger in ctx.loggers.iter() {
            logger.log(&log_ctx);
        }
    }
}

fn format_system_time(time: SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(time).to_rfc3339()
}

fn metadata_termination(
    flags: &[ResponseFlag],
    status: u16,
    local: bool,
) -> proxy_observability::records::Termination {
    use proxy_observability::records::Termination;
    if flags.contains(&ResponseFlag::DownstreamConnectionTermination) {
        Termination::DownstreamDisconnect
    } else if flags.iter().any(|f| {
        matches!(
            f,
            ResponseFlag::StreamIdleTimeout | ResponseFlag::UpstreamRequestTimeout
        )
    }) {
        Termination::Timeout
    } else if flags.contains(&ResponseFlag::UpstreamConnectionTermination) || status >= 500 {
        Termination::UpstreamError
    } else if local {
        Termination::LocalReply
    } else {
        Termination::Complete
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Body for LoggingBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // Rust note: same "no manual pin projection needed" shape as
        // `GuardedBody`/`IdleTimeoutBody` -- every field here is `Unpin`.
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_frame(cx);
        match &poll {
            Poll::Ready(Some(Ok(frame))) => {
                let mut finished_by_length = false;
                if let Some(data) = frame.data_ref() {
                    this.bytes_sent += data.len() as u64;
                    finished_by_length = this.note_frame_len(data.len());
                }
                if let Some(trailers) = frame.trailers_ref() {
                    this.trailers = trailers.clone();
                }
                // See `note_frame_len`'s doc: this frame is the one hyper's
                // write dispatcher will never poll past, so treat it as the
                // clean end right here rather than waiting for a `None` that
                // is never coming.
                if finished_by_length {
                    this.finish();
                }
            }
            // A clean end-of-stream needs no flag -- see the `Err` arm below
            // for the failure case.
            Poll::Ready(None) => this.finish(),
            // An error is terminal too, but -- unlike a clean end -- it's a
            // failure an operator needs visible in the access log: classify
            // it into a `ResponseFlag` and warn *before* `finish()` snapshots
            // the flags (see `record_failure`'s doc for why the ordering
            // matters).
            Poll::Ready(Some(Err(err))) => {
                let flag = Self::classify(err);
                this.record_failure(flag, err);
                this.finish();
            }
            Poll::Pending => {}
        }
        poll
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for LoggingBody {
    fn drop(&mut self) {
        // Covers the abandoned-stream case: a disconnecting client, or an
        // outer combinator dropping this body before it ever reached
        // end-of-stream/error through `poll_frame`. `self.ctx` is still
        // `Some` here exactly when neither `poll_frame` arm above ran to
        // completion -- i.e. the stream never cleanly ended and never
        // errored, it was simply given up on. That's a downstream
        // termination from the operator's point of view (the far end went
        // away without us ever seeing why), same as Envoy's DC.
        if self.ctx.is_some() {
            self.record_failure(
                ResponseFlag::DownstreamConnectionTermination,
                &"response body dropped before end-of-stream",
            );
        }
        // `finish` is idempotent (`ctx.take()`), so this is a no-op if
        // `poll_frame` already logged.
        self.finish();
    }
}

// `CountingRequestBody` (a streaming-body wrapper that incremented
// `stream_info.bytes_received` frame-by-frame as the downstream request body
// was forwarded upstream) lived here until ADR-0004 step 3. It's gone now,
// not orphaned: `router::RouterHandler` no longer streams the request body at
// all -- decode is always fully buffered before the terminal runs (see
// `filter_manager`'s module doc), so `router::apply_forward` sets
// `bytes_received` directly from the already-known buffer length instead
// (`dcb.stream_info().bytes_received = body_bytes.len() as u64`). Removed
// (rather than left `#[allow(dead_code)]`) because clippy's `-D warnings`
// gate is right that nothing constructs it anymore.

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use bytes::Bytes;
    use http::{HeaderMap, StatusCode};
    use http_body_util::{BodyExt, Full};
    use proxy_observability::access_log::parse_format;
    use proxy_observability::sink::AccessLogWriter;

    use super::*;
    use crate::handler::local_boxed;
    use crate::stream_info::LlmTokenUsage;

    /// An in-memory sink for asserting on rendered lines, standing in for
    /// `FileSink`/`StdoutSink` -- same trait, no I/O.
    ///
    /// Rust note: `Mutex<Vec<String>>` behind an `Arc` so the test can hold
    /// its own clone to inspect after the sink has been moved into an
    /// `AccessLoggerRuntime` as `Arc<dyn AccessLogWriter>`.
    #[derive(Default)]
    struct CaptureSink(Mutex<Vec<String>>);

    impl AccessLogWriter for CaptureSink {
        fn write_line(&self, line: &str) {
            self.0.lock().unwrap().push(line.to_string());
        }
        fn flush(&self) {}
        fn reopen(&self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Drives one `LoggingBody` (a response body plus its populated
    /// `StreamInfo::llm`) to completion and returns the single rendered
    /// line, proving the token/TTFT operators reach the real access
    /// log through the same path as `bytes_sent` -- not just through
    /// `access_log::render` in isolation.
    async fn render_one(llm: crate::stream_info::LlmStats) -> String {
        render_one_fmt(
            "%LLM_INPUT_TOKENS% %LLM_CACHED_TOKENS% %LLM_CACHE_CREATION_TOKENS% %LLM_OUTPUT_TOKENS% %LLM_TOTAL_TOKENS% %LLM_TTFT%",
            llm,
        )
        .await
    }

    /// Same as [`render_one`], but with a caller-supplied format string --
    /// used by the TPOT/max-stall tests below to exercise `%LLM_TPOT%`/
    /// `%LLM_MAX_STALL%`/`%LLM_RESPONSE_CHUNKS%` end-to-end (`StreamInfo` ->
    /// `AccessLogContext` -> the rendered line), not from a hand-built
    /// `LogContext`.
    async fn render_one_fmt(fmt: &str, llm: crate::stream_info::LlmStats) -> String {
        render_with_stream_info(fmt, move |info| info.llm = llm).await
    }

    /// Same as [`render_one_fmt`], but the caller shapes the `StreamInfo`
    /// (through the same `Rc<RefCell<..>>` the router writes to) before the
    /// body is driven to end-of-stream.
    async fn render_with_stream_info(fmt: &str, configure: impl FnOnce(&mut StreamInfo)) -> String {
        let capture = Arc::new(CaptureSink::default());
        drive_one_response(capture.clone() as Arc<dyn AccessLogWriter>, fmt, configure).await;
        let mut lines = capture.0.lock().unwrap();
        assert_eq!(lines.len(), 1, "expected exactly one rendered line");
        lines.remove(0)
    }

    /// Drive one response body to end-of-stream through a `LoggingBody`
    /// logging to `sink` (the real finish path, not a hand-built context).
    async fn drive_one_response(
        sink: Arc<dyn AccessLogWriter>,
        fmt: &str,
        configure: impl FnOnce(&mut StreamInfo),
    ) {
        let fmt = parse_format(fmt).unwrap();
        let logger = AccessLoggerRuntime {
            sink,
            format: AccessLogFormat::Text(fmt),
            filter: None,
        };

        let mut stream_info = StreamInfo::default();
        configure(&mut stream_info);

        let ctx = AccessLogContext {
            loggers: Rc::new(vec![logger]),
            stream_info: Rc::new(RefCell::new(stream_info)),
            start_time: SystemTime::now(),
            start_instant: Instant::now(),
            request: RequestSnapshot {
                headers: HeaderMap::new(),
                method: "GET".to_string(),
                path: "/".to_string(),
                authority: None,
                scheme: None,
            },
            response_headers: HeaderMap::new(),
            response_code: StatusCode::OK.as_u16(),
            downstream_remote_address: "127.0.0.1:0".to_string(),
            token_stats: None,
            latency_stats: None,
            span_sink: None,
            request_record_sink: None,
        };

        let body = local_boxed(
            Full::new(Bytes::from_static(b"hi"))
                .map_err(|infallible: std::convert::Infallible| match infallible {}),
        );
        let logging_body = LoggingBody::new(body, ctx);
        // Drain to end-of-stream, which is what triggers `finish()`.
        let _ = logging_body.collect().await.unwrap();
    }

    /// An inner sink whose `write_line` parks until the test opens the gate,
    /// standing in for a stalled stdout pipe or a hung disk.
    struct GatedSink {
        gate: Mutex<std::sync::mpsc::Receiver<()>>,
        lines: Arc<Mutex<Vec<String>>>,
    }

    impl AccessLogWriter for GatedSink {
        fn write_line(&self, line: &str) {
            // Blocks until the test sends (or drops the sender).
            let _ = self.gate.lock().unwrap().recv();
            self.lines.lock().unwrap().push(line.to_string());
        }
        fn flush(&self) {}
        fn reopen(&self) -> io::Result<()> {
            Ok(())
        }
    }

    // Worker-level proof that a blocked log destination cannot stall request
    // completion: three responses finish on one single-threaded runtime while
    // the inner sink's first write is parked, then every line arrives in order
    // once the destination recovers.
    #[tokio::test(flavor = "current_thread")]
    async fn a_blocked_log_destination_does_not_stall_responses_on_the_worker() {
        let (open_gate, gate) = std::sync::mpsc::channel();
        let lines = Arc::new(Mutex::new(Vec::new()));
        let inner = Arc::new(GatedSink {
            gate: Mutex::new(gate),
            lines: lines.clone(),
        });
        let sink: Arc<dyn AccessLogWriter> =
            Arc::new(proxy_observability::sink::QueuedSink::new("gated", inner).unwrap());

        for _ in 0..3 {
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                drive_one_response(sink.clone(), "%RESPONSE_CODE%\n", |_| {}),
            )
            .await
            .expect("response must complete while the log destination is blocked");
        }
        assert!(
            lines.lock().unwrap().is_empty(),
            "the destination is still parked, nothing was written"
        );

        for _ in 0..3 {
            open_gate.send(()).unwrap();
        }
        sink.flush();
        assert_eq!(*lines.lock().unwrap(), vec!["200\n"; 3]);
    }

    #[tokio::test]
    async fn credential_source_reaches_the_rendered_access_log_line() {
        // The router sets `StreamInfo::credential_source` at the credential
        // step; the access log must render that value, not a re-derived one.
        assert_eq!(
            render_with_stream_info("%LLM_CREDENTIAL_SOURCE%", |info| {
                info.credential_source = Some(CredentialSource::Tenant);
            })
            .await,
            "tenant"
        );
        assert_eq!(
            render_with_stream_info("%LLM_CREDENTIAL_SOURCE%", |info| {
                info.credential_source = Some(CredentialSource::Platform);
            })
            .await,
            "platform"
        );
        // A request that never reached the credential step renders `-`.
        assert_eq!(
            render_with_stream_info("%LLM_CREDENTIAL_SOURCE%", |_| {}).await,
            "-"
        );
    }

    #[tokio::test]
    async fn served_model_reaches_the_rendered_access_log_line() {
        assert_eq!(
            render_with_stream_info("%LLM_SERVED_MODEL%", |info| {
                info.llm.served_model = Some("gpt-4o-mini-2024-07-18".into());
            })
            .await,
            "gpt-4o-mini-2024-07-18"
        );
        assert_eq!(
            render_with_stream_info("%LLM_SERVED_MODEL%", |_| {}).await,
            "-"
        );
    }

    #[tokio::test]
    async fn llm_stats_reach_the_rendered_access_log_line() {
        let llm = crate::stream_info::LlmStats {
            usage: Some(LlmTokenUsage {
                input_tokens: 11,
                cached_tokens: 22,
                cache_creation_tokens: 33,
                output_tokens: 44,
            }),
            list_cost: None,
            served_model: None,
            system: None,
            time_to_first_byte: Some(std::time::Duration::from_millis(250)),
            time_to_first_body_byte: None,
            max_inter_chunk: None,
            response_chunks: 1,
        };
        assert_eq!(render_one(llm).await, "11 22 33 44 110 250");
    }

    #[tokio::test]
    async fn absent_llm_stats_render_dash_not_zero() {
        // A stream that never populated `StreamInfo::llm` (a non-LLM
        // route, or a provider response with no usage) must log `-`, not a
        // confident-looking `0` -- these numbers feed billing.
        assert_eq!(
            render_one(crate::stream_info::LlmStats::default()).await,
            "- - - - - -"
        );
    }

    #[tokio::test]
    async fn immutable_list_cost_reaches_the_real_access_log_line() {
        let llm = crate::stream_info::LlmStats {
            list_cost: Some(crate::stream_info::LlmListCost {
                nanodollars: 987_654,
                rate_card_version: "v1+abcdef".into(),
            }),
            ..Default::default()
        };
        assert_eq!(render_one_fmt("%LLM_LIST_COST%", llm).await, "987654");
    }

    #[tokio::test]
    async fn metadata_usage_and_list_cost_belong_only_to_the_selected_attempt() {
        let version = format!("operator-{}+content-hash", "v".repeat(600));
        let capture = Arc::new(CaptureSink::default());
        let mut ctx = flags_ctx(&capture);
        let (sink, mut records) = proxy_observability::records::BoundedRecordSink::new(1);
        ctx.request_record_sink = Some(Arc::new(sink));
        {
            let mut info = ctx.stream_info.borrow_mut();
            info.metadata_enabled = true;
            let failed = info.begin_attempt("primary", "host", None).unwrap();
            failed
                .borrow_mut()
                .finish(proxy_observability::records::Termination::UpstreamError);
            let selected = info
                .begin_attempt("fallback", "host", Some("upstream-model".into()))
                .unwrap();
            selected.borrow_mut().served_model = Some("upstream-model-2024-07-18".into());
            info.selected_attempt = Some(selected);
            info.upstream_cluster = Some("fallback".into());
            info.llm.usage = Some(LlmTokenUsage {
                input_tokens: 10,
                cached_tokens: 2,
                cache_creation_tokens: 3,
                output_tokens: 4,
            });
            info.llm.list_cost = Some(crate::stream_info::LlmListCost {
                nanodollars: 987_654,
                rate_card_version: version.clone(),
            });
        }
        let body = local_boxed(
            Full::new(Bytes::from_static(b"hi"))
                .map_err(|never: std::convert::Infallible| match never {}),
        );
        LoggingBody::new(body, ctx).collect().await.unwrap();
        let record = records.try_recv().unwrap();
        assert!(record.attempts[0].usage.is_none());
        assert!(record.attempts[0].cost.is_none());
        assert_eq!(record.attempts[1].usage, record.usage);
        assert_eq!(record.attempts[1].cost, record.cost);
        // The served model is the selected attempt's evidence, not the failed one's.
        assert_eq!(record.attempts[0].served_model, None);
        assert_eq!(
            record.attempts[1].served_model.as_deref(),
            Some("upstream-model-2024-07-18")
        );
        let cost = record.cost.unwrap();
        assert_eq!(cost.amount, 987_654);
        assert_eq!(cost.unit, "nanodollars");
        assert_eq!(cost.kind, "list");
        assert_eq!(cost.rate_card_version, version);
        assert!(records.try_recv().is_err());
    }

    #[tokio::test]
    async fn a_malformed_terminal_record_is_counted_invalid_not_silently_dropped() {
        let capture = Arc::new(CaptureSink::default());
        let mut ctx = flags_ctx(&capture);
        let (sink, mut records) = proxy_observability::records::BoundedRecordSink::new(1);
        let counters = sink.counters();
        ctx.request_record_sink = Some(Arc::new(sink));
        {
            let mut info = ctx.stream_info.borrow_mut();
            info.metadata_enabled = true;
            info.begin_attempt("primary", "host", None).unwrap();
            // Fewer physical attempts than recorded ones is impossible in
            // production; `validate` rejects it regardless of sink limits.
            info.physical_attempt_count = 0;
        }
        LoggingBody::new(
            local_boxed(
                Full::new(Bytes::new()).map_err(|never: std::convert::Infallible| match never {}),
            ),
            ctx,
        )
        .collect()
        .await
        .unwrap();
        assert!(records.try_recv().is_err());
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.invalid, 1);
        assert_eq!(snapshot.capacity_exceeded + snapshot.oversize, 0);
    }

    #[tokio::test]
    async fn metadata_identity_uses_auth_and_never_usage_dialect() {
        let capture = Arc::new(CaptureSink::default());
        let mut ctx = flags_ctx(&capture);
        let (sink, mut records) = proxy_observability::records::BoundedRecordSink::new(1);
        ctx.request_record_sink = Some(Arc::new(sink));
        {
            let mut info = ctx.stream_info.borrow_mut();
            info.auth.tenant = Some("authenticated-tenant".into());
            info.auth.key_id = Some("k".repeat(4096));
            info.llm.system = Some(crate::stream_info::GenAiSystem::OpenAi);
            info.upstream_usage_dialect = Some(proxy_config::ir::UsageDialect::OpenAi);
            info.set_response_flag(ResponseFlag::NoRouteFound);
            info.set_response_flag(ResponseFlag::NoRouteFound);
        }
        LoggingBody::new(
            local_boxed(
                Full::new(Bytes::new()).map_err(|never: std::convert::Infallible| match never {}),
            ),
            ctx,
        )
        .collect()
        .await
        .unwrap();
        let record = records.try_recv().unwrap();
        assert_eq!(record.tenant_id, "authenticated-tenant");
        assert_eq!(record.key_id.unwrap().len(), 512);
        assert!(record.user_id.is_none());
        assert!(record.selected_provider.is_none());
        assert!(record.usage.is_none());
        assert!(record.cost.is_none());
        assert_eq!(record.response_flags, ["NR"]);
        assert!(records.try_recv().is_err());
    }

    // --- llm token-usage recording plumbing -------------------------------
    //
    // These prove `LoggingBody::finish` actually calls into a wired
    // `GenAiTokenStats` with the right provider and per-bucket values -- not
    // just that `access_log::render` can format `LlmTokens` (already covered
    // above). `flags_ctx` is defined further down this file (mid-stream
    // failure tests); Rust doesn't require definition order within a module.

    use crate::stat_handles::{GenAiTokenStats, TokenUsageStatHandles};
    use proxy_observability::stats::{Registry, StatsControl, WorkerId as StatsWorkerId};

    /// Builds a `GenAiTokenStats` resolved for `provider`, handing back the
    /// underlying `Registry` too so a test can read `Registry::value`
    /// straight off the resolved handles.
    fn token_stats_for(
        provider: &str,
    ) -> (
        Arc<GenAiTokenStats>,
        Arc<TokenUsageStatHandles>,
        Arc<Registry>,
    ) {
        let control = StatsControl::new(1);
        let handles = Arc::new(TokenUsageStatHandles::build(&control, [provider]));
        let registry = control.registry();
        let stats = Arc::new(GenAiTokenStats::new(
            registry.clone(),
            handles.clone(),
            StatsWorkerId(0),
        ));
        (stats, handles, registry)
    }

    /// Drives a `LoggingBody` seeded with `usage`/`upstream_cluster`/`tenant`
    /// and a wired `token_stats` to completion (`finish()` via clean
    /// end-of-stream). `tenant` seeds `StreamInfo::auth.tenant` -- the SAME
    /// field the real auth filter writes -- exercised by this test
    /// module going through the real `LoggingBody::finish` path, not a
    /// direct `GenAiTokenStats::record_usage` call.
    async fn drive_with_usage_and_provider(
        token_stats: Option<Arc<GenAiTokenStats>>,
        upstream_cluster: Option<&str>,
        tenant: Option<&str>,
        usage: Option<LlmTokenUsage>,
    ) {
        let capture = Arc::new(CaptureSink::default());
        let mut ctx = flags_ctx(&capture);
        ctx.token_stats = token_stats;
        {
            let mut info = ctx.stream_info.borrow_mut();
            info.upstream_cluster = upstream_cluster.map(str::to_string);
            info.llm.usage = usage;
            info.auth.tenant = tenant.map(str::to_string);
        }
        let body = local_boxed(
            Full::new(Bytes::from_static(b"hi"))
                .map_err(|infallible: std::convert::Infallible| match infallible {}),
        );
        let _ = LoggingBody::new(body, ctx).collect().await.unwrap();
    }

    #[tokio::test]
    async fn usage_reaches_llm_token_stats_against_the_dialled_provider() {
        let (token_stats, handles, registry) = token_stats_for("openai-fallback");

        drive_with_usage_and_provider(
            Some(token_stats),
            Some("openai-fallback"),
            None,
            Some(LlmTokenUsage {
                input_tokens: 40,
                cached_tokens: 10,
                cache_creation_tokens: 0,
                output_tokens: 7,
            }),
        )
        .await;

        let h = handles.for_provider("openai-fallback").unwrap();
        assert_eq!(registry.value(h.input), 40);
        assert_eq!(registry.value(h.cached), 10);
        assert_eq!(registry.value(h.cache_creation), 0);
        assert_eq!(registry.value(h.output), 7);
    }

    #[tokio::test]
    async fn no_usage_records_nothing_even_with_a_wired_recorder() {
        // The gap this closes if it regresses: "no usage was reported" and
        // "zero tokens were used" are different facts, and this must not
        // synthesize the second from the absence of the first.
        let (token_stats, handles, registry) = token_stats_for("openai");

        drive_with_usage_and_provider(Some(token_stats), Some("openai"), None, None).await;

        let h = handles.for_provider("openai").unwrap();
        assert_eq!(registry.value(h.input), 0);
        assert_eq!(registry.value(h.output), 0);
    }

    // --- `tenant` reaches `LLM_CLIENT_TOKEN_USAGE` through the real
    // `StreamInfo::auth.tenant` -> `LoggingBody::finish` path -------------

    #[tokio::test]
    async fn an_authenticated_tenant_reaches_llm_token_stats_with_its_own_id() {
        // Requirement 1: the resolved tenant id, end to end through
        // `LoggingBody::finish` -- `StreamInfo::auth.tenant` is set exactly
        // the way the auth filter sets it (a plain `Option<String>`, see
        // `stream_info::AuthInfo`'s own doc), not through a shortcut.
        let (token_stats, _handles, registry) = token_stats_for("openai");

        drive_with_usage_and_provider(
            Some(token_stats),
            Some("openai"),
            Some("acme-corp"),
            Some(LlmTokenUsage {
                input_tokens: 40,
                cached_tokens: 10,
                cache_creation_tokens: 0,
                output_tokens: 7,
            }),
        )
        .await;

        let h = registry.resolve_capped(
            &proxy_observability::stats::instruments::LLM_CLIENT_TOKEN_USAGE,
            &[
                ("provider", "openai"),
                ("type", "input"),
                ("tenant", "acme-corp"),
            ],
            proxy_observability::stats::instruments::LLM_CLIENT_TOKEN_USAGE_TENANT_CEILING,
            &[
                ("provider", "openai"),
                ("type", "input"),
                (
                    "tenant",
                    proxy_observability::stats::instruments::LLM_CLIENT_TOKEN_USAGE_TENANT_CARDINALITY_OVERFLOW,
                ),
            ],
        );
        assert_eq!(
            registry.value(h),
            40,
            "usage must land on the AUTHENTICATED tenant's own series"
        );
    }

    #[tokio::test]
    async fn an_unauthenticated_stream_records_under_the_no_tenant_sentinel_not_a_real_tenant() {
        // Requirement 2, driven through the real path (not a direct
        // `record_usage` call, see `stat_handles`'s own coverage of that):
        // `tenant: None` still counts, and lands on the sentinel series
        // `TokenUsageStatHandles::for_provider` pre-resolves.
        let (token_stats, handles, registry) = token_stats_for("openai");

        drive_with_usage_and_provider(
            Some(token_stats),
            Some("openai"),
            None,
            Some(LlmTokenUsage {
                input_tokens: 5,
                cached_tokens: 0,
                cache_creation_tokens: 0,
                output_tokens: 3,
            }),
        )
        .await;

        let h = handles.for_provider("openai").unwrap();
        assert_eq!(
            registry.value(h.input),
            5,
            "unauthenticated usage must still be recorded"
        );
    }

    /// Requirement 4 (rule 17): trace `tenant` back to its ONLY source at
    /// this layer, `StreamInfo::auth.tenant`, and confirm by type that it
    /// cannot carry credential material -- `AuthInfo::tenant` is a plain
    /// `Option<String>` (see `stream_info::AuthInfo`'s own doc: "What
    /// crosses is deliberately only the two *identifiers*"), not a
    /// `LimitKey`/`CredentialDigest`/anything key-shaped. This test drives
    /// the exact value that ends up as the `tenant` attribute through the
    /// real `finish()` path and confirms it is untransformed.
    #[tokio::test]
    async fn no_credential_material_reaches_the_tenant_attribute() {
        let (token_stats, _handles, registry) = token_stats_for("openai");

        // A value shaped like a virtual-key credential (see
        // `proxy_filters::auth::KEY_PREFIX`) -- if anything on this path
        // hashed, digested, or otherwise substituted the credential for the
        // tenant id, this exact string would not be the one that resolves a
        // series with the recorded usage on it.
        let tenant_that_looks_like_a_key = "llmp_definitely-not-a-tenant-id";

        drive_with_usage_and_provider(
            Some(token_stats),
            Some("openai"),
            Some(tenant_that_looks_like_a_key),
            Some(LlmTokenUsage {
                input_tokens: 9,
                cached_tokens: 0,
                cache_creation_tokens: 0,
                output_tokens: 1,
            }),
        )
        .await;

        let h = registry.resolve_capped(
            &proxy_observability::stats::instruments::LLM_CLIENT_TOKEN_USAGE,
            &[
                ("provider", "openai"),
                ("type", "input"),
                ("tenant", tenant_that_looks_like_a_key),
            ],
            proxy_observability::stats::instruments::LLM_CLIENT_TOKEN_USAGE_TENANT_CEILING,
            &[
                ("provider", "openai"),
                ("type", "input"),
                (
                    "tenant",
                    proxy_observability::stats::instruments::LLM_CLIENT_TOKEN_USAGE_TENANT_CARDINALITY_OVERFLOW,
                ),
            ],
        );
        assert_eq!(
            registry.value(h),
            9,
            "the exact string in `StreamInfo::auth.tenant` must be the attribute value -- a \
             hash/digest would resolve a different series and find nothing here"
        );
    }

    // --- TPOT / max-stall / response-chunks plumbing ---------------
    //
    // These drive the real `StreamInfo` -> `AccessLogContext` -> `LoggingBody`
    // path (via `render_one_fmt`), not a hand-built `LogContext` -- the
    // plumbing from `StreamInfo::llm` through to `LogContext` is exactly the
    // part TPOT/max-stall adds, so it's the part worth exercising end-to-end.

    #[tokio::test]
    async fn llm_max_stall_and_response_chunks_reach_the_rendered_line() {
        let llm = crate::stream_info::LlmStats {
            usage: None,
            list_cost: None,
            served_model: None,
            system: None,
            time_to_first_byte: None,
            time_to_first_body_byte: None,
            max_inter_chunk: Some(std::time::Duration::from_millis(150)),
            response_chunks: 7,
        };
        assert_eq!(
            render_one_fmt("%LLM_MAX_STALL% %LLM_RESPONSE_CHUNKS%", llm).await,
            "150 7"
        );
    }

    #[tokio::test]
    async fn llm_max_stall_renders_dash_when_absent_response_chunks_renders_zero() {
        let llm = crate::stream_info::LlmStats::default();
        assert_eq!(
            render_one_fmt("%LLM_MAX_STALL% %LLM_RESPONSE_CHUNKS%", llm).await,
            "- 0"
        );
    }

    #[tokio::test]
    async fn llm_tpot_reaches_the_rendered_line_via_real_stream_info() {
        // Not a hand-built `LogContext`: `duration` here is the real elapsed
        // wall time `LoggingBody` measures from `start_instant` to
        // end-of-stream, so this only proves the plumbing (usage, ttft, and
        // duration all reach `%LLM_TPOT%` through the real path) -- the exact
        // formula is proven precisely, against a scripted `LogContext`, in
        // `proxy_observability::access_log`'s own tests.
        let llm = crate::stream_info::LlmStats {
            usage: Some(LlmTokenUsage {
                input_tokens: 1,
                cached_tokens: 0,
                cache_creation_tokens: 0,
                output_tokens: 10,
            }),
            list_cost: None,
            served_model: None,
            system: None,
            time_to_first_byte: Some(std::time::Duration::from_millis(0)),
            time_to_first_body_byte: None,
            max_inter_chunk: None,
            response_chunks: 1,
        };
        let line = render_one_fmt("%LLM_TPOT%", llm).await;
        assert_ne!(line, "-", "usage + ttft + duration are all present");
        // TPOT renders fractional milliseconds (`<ms>.<micros>`) so that a
        // sub-millisecond-per-token stream does not collapse to 0 -- see
        // `access_log::tests::llm_tpot_keeps_sub_millisecond_precision_for_fast_streams`
        // for why. This test only proves the value REACHES the line through the
        // real StreamInfo path; the exact formula is pinned in `access_log.rs`.
        let (ms, micros) = line
            .split_once('.')
            .unwrap_or_else(|| panic!("expected `<ms>.<micros>`, got {line:?}"));
        ms.parse::<u128>()
            .unwrap_or_else(|_| panic!("millisecond part not numeric in {line:?}"));
        assert_eq!(micros.len(), 3, "micros must be zero-padded to 3 digits");
        micros
            .parse::<u128>()
            .unwrap_or_else(|_| panic!("micros part not numeric in {line:?}"));
    }

    // --- mid-stream body failure visibility -------------------------------
    //
    // The gap these tests close: a response body that errors (or is dropped)
    // *after* headers have already gone downstream used to leave
    // `StreamInfo::response_flags` empty -- an SSE stream killed by the
    // network logged byte-identical to a short-but-successful completion.
    // See `LoggingBody::classify`/`record_failure`.

    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context as TaskContext, Poll};
    use std::time::Duration;

    use crate::router::idle::IdleTimeoutBody;

    /// A minimal [`tracing::Subscriber`] that only counts WARN-level events
    /// -- enough to prove "a mid-stream failure warns" and "a clean end does
    /// not warn" without pulling in a tracing-capture crate as a new
    /// dev-dependency.
    struct WarnCounter(Arc<AtomicUsize>);

    impl tracing::Subscriber for WarnCounter {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if *event.metadata().level() == tracing::Level::WARN {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}
    }

    /// Builds a bare-bones [`AccessLogContext`] rendering just
    /// `%RESPONSE_FLAGS% %BYTES_SENT%`, wired to `capture`.
    fn flags_ctx(capture: &Arc<CaptureSink>) -> AccessLogContext {
        let fmt = parse_format("%RESPONSE_FLAGS% %BYTES_SENT%").unwrap();
        let logger = AccessLoggerRuntime {
            sink: capture.clone() as Arc<dyn AccessLogWriter>,
            format: AccessLogFormat::Text(fmt),
            filter: None,
        };
        AccessLogContext {
            loggers: Rc::new(vec![logger]),
            stream_info: Rc::new(RefCell::new(StreamInfo::default())),
            start_time: SystemTime::now(),
            start_instant: Instant::now(),
            request: RequestSnapshot {
                headers: HeaderMap::new(),
                method: "GET".to_string(),
                path: "/".to_string(),
                authority: None,
                scheme: None,
            },
            response_headers: HeaderMap::new(),
            response_code: StatusCode::OK.as_u16(),
            downstream_remote_address: "127.0.0.1:0".to_string(),
            // This helper renders only %RESPONSE_FLAGS% %BYTES_SENT%, so it
            // has no reason to record token usage; `None` is the "no
            // recorder wired" case, which is also what an HCM without stats
            // produces in production.
            token_stats: None,
            latency_stats: None,
            span_sink: None,
            request_record_sink: None,
        }
    }

    #[tokio::test]
    async fn successful_llm_stream_reaches_both_gen_ai_latency_histograms() {
        let capture = Arc::new(CaptureSink::default());
        let control = proxy_observability::stats::StatsControl::new(1);
        let registry = control.registry();
        let mut ctx = flags_ctx(&capture);
        ctx.request.path = "/v1/chat/completions".to_string();
        ctx.start_instant = Instant::now() - std::time::Duration::from_secs(1);
        ctx.latency_stats = Some(Arc::new(GenAiLatencyStats::new(
            registry.clone(),
            proxy_observability::stats::WorkerId(0),
        )));
        {
            let mut info = ctx.stream_info.borrow_mut();
            info.requested_model = Some("gpt-4o".to_string());
            info.llm.system = Some(crate::stream_info::GenAiSystem::OpenAi);
            info.llm.time_to_first_body_byte = Some(std::time::Duration::from_millis(100));
            info.llm.usage = Some(LlmTokenUsage {
                input_tokens: 1,
                cached_tokens: 0,
                cache_creation_tokens: 0,
                output_tokens: 5,
            });
        }

        let body = local_boxed(
            Full::new(Bytes::from_static(b"hi"))
                .map_err(|infallible: std::convert::Infallible| match infallible {}),
        );
        let _ = LoggingBody::new(body, ctx).collect().await.unwrap();

        for name in [
            "gen_ai.server.time_to_first_token",
            "gen_ai.server.time_per_output_token",
        ] {
            let (handle, _, attrs) = registry
                .histograms()
                .find(|(_, instrument, _)| instrument.name == name)
                .unwrap_or_else(|| panic!("missing {name}"));
            assert!(attrs.contains(&("gen_ai.request.model".to_string(), "gpt-4o".to_string())));
            assert_eq!(registry.histogram_snapshot(handle).count, 1);
        }
    }

    /// A body that yields one `"hi"` data frame, then a configurable error.
    struct OneFrameThenError {
        frame: Option<Bytes>,
        err: Option<BodyError>,
    }

    impl hyper::body::Body for OneFrameThenError {
        type Data = Bytes;
        type Error = BodyError;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            let this = self.get_mut();
            if let Some(data) = this.frame.take() {
                return Poll::Ready(Some(Ok(Frame::data(data))));
            }
            if let Some(err) = this.err.take() {
                return Poll::Ready(Some(Err(err)));
            }
            Poll::Ready(None)
        }

        fn is_end_stream(&self) -> bool {
            self.frame.is_none() && self.err.is_none()
        }

        fn size_hint(&self) -> hyper::body::SizeHint {
            hyper::body::SizeHint::default()
        }
    }

    /// A body that yields one `"hi"` data frame, then goes `Pending` forever
    /// -- stands in for an SSE stream whose connection dies without ever
    /// producing another frame or an explicit error, i.e. the "abandoned"
    /// case `Drop` (not `poll_frame`) has to catch.
    struct FrameThenPendingForever {
        frame: Option<Bytes>,
    }

    impl hyper::body::Body for FrameThenPendingForever {
        type Data = Bytes;
        type Error = BodyError;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            let this = self.get_mut();
            if let Some(data) = this.frame.take() {
                return Poll::Ready(Some(Ok(Frame::data(data))));
            }
            Poll::Pending
        }

        fn is_end_stream(&self) -> bool {
            false
        }

        fn size_hint(&self) -> hyper::body::SizeHint {
            hyper::body::SizeHint::default()
        }
    }

    /// A body that never produces a frame -- the inner body an idle-timeout
    /// wrapper sits on top of, so the *only* way `IdleTimeoutBody` ever
    /// resolves is via its own timer, not via this body doing anything.
    struct NeverBody;

    impl hyper::body::Body for NeverBody {
        type Data = Bytes;
        type Error = BodyError;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Pending
        }

        fn is_end_stream(&self) -> bool {
            false
        }

        fn size_hint(&self) -> hyper::body::SizeHint {
            hyper::body::SizeHint::default()
        }
    }

    #[tokio::test]
    async fn upstream_body_error_mid_stream_logs_uc() {
        let capture = Arc::new(CaptureSink::default());
        let counter = Arc::new(AtomicUsize::new(0));
        let guard = tracing::subscriber::set_default(WarnCounter(counter.clone()));

        let body = local_boxed(OneFrameThenError {
            frame: Some(Bytes::from_static(b"hi")),
            err: Some(BodyError::Upstream(Box::new(io::Error::other(
                "connection reset by peer",
            )))),
        });
        let logging_body = LoggingBody::new(body, flags_ctx(&capture));
        // The inner error surfaces through `collect()` too -- draining is
        // exactly what a real response-forwarding loop does.
        assert!(logging_body.collect().await.is_err());

        drop(guard);
        let mut lines = capture.0.lock().unwrap();
        assert_eq!(lines.len(), 1, "expected exactly one rendered line");
        assert_eq!(lines.remove(0), "UC 2");
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "a mid-stream failure must warn exactly once"
        );
    }

    #[tokio::test]
    async fn downstream_body_error_mid_stream_logs_dc() {
        let capture = Arc::new(CaptureSink::default());
        let body = local_boxed(OneFrameThenError {
            frame: Some(Bytes::from_static(b"hi")),
            err: Some(BodyError::Downstream(Box::new(io::Error::other(
                "client disconnected",
            )))),
        });
        let logging_body = LoggingBody::new(body, flags_ctx(&capture));
        assert!(logging_body.collect().await.is_err());

        let mut lines = capture.0.lock().unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines.remove(0), "DC 2");
    }

    #[tokio::test]
    async fn idle_timeout_body_error_logs_si_not_uc() {
        // The regression-prone case: `IdleTimeoutBody` reports its timeout
        // through the same `BodyError::Upstream` variant a dead TCP
        // connection would use -- classification has to downcast the boxed
        // source to `IdleTimeoutError` to tell "went quiet" (SI) apart from
        // "connection died" (UC).
        let capture = Arc::new(CaptureSink::default());
        let inner = local_boxed(NeverBody);
        let body = local_boxed(IdleTimeoutBody::new(inner, Duration::from_millis(5)));
        let logging_body = LoggingBody::new(body, flags_ctx(&capture));

        tokio::time::timeout(Duration::from_secs(2), async {
            assert!(logging_body.collect().await.is_err());
        })
        .await
        .expect("idle timeout must fire well within the guard timeout");

        let mut lines = capture.0.lock().unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines.remove(0), "SI 0");
    }

    #[test]
    fn body_dropped_before_end_of_stream_logs_dc() {
        let capture = Arc::new(CaptureSink::default());
        let body = local_boxed(FrameThenPendingForever {
            frame: Some(Bytes::from_static(b"hi")),
        });
        let mut logging_body = LoggingBody::new(body, flags_ctx(&capture));

        let waker = futures::task::noop_waker();
        let mut cx = TaskContext::from_waker(&waker);
        // First poll: the one real frame -- not terminal, `ctx` stays `Some`.
        match Pin::new(&mut logging_body).poll_frame(&mut cx) {
            Poll::Ready(Some(Ok(_))) => {}
            other => panic!("expected the frame, got {other:?}"),
        }
        // Second poll: the body never resolves again from here on (this is
        // the "abandoned mid-flight" shape -- a client disconnect, or an
        // outer combinator giving up, neither of which drives this body to
        // `None`/`Err` through `poll_frame`).
        assert!(matches!(
            Pin::new(&mut logging_body).poll_frame(&mut cx),
            Poll::Pending
        ));

        // Dropped without ever reaching end-of-stream or an error.
        drop(logging_body);

        let mut lines = capture.0.lock().unwrap();
        assert_eq!(lines.len(), 1, "Drop must still render exactly one line");
        assert_eq!(
            lines.remove(0),
            "DC 2",
            "bytes_sent must reflect the one frame delivered before the drop"
        );
    }

    /// The defect this file's `note_frame_len`/`remaining_content_length`
    /// exist to fix: a `content-length`-framed response whose body NEVER
    /// gets polled again once the declared length is satisfied -- exactly
    /// what hyper's real HTTP/1 write dispatcher does, and exactly what
    /// `FrameThenPendingForever` stands in for above (it goes `Pending`
    /// forever after its one frame, same as `body_dropped_before_end_of_
    /// stream_logs_dc`) -- must still log a CLEAN end, not `DC`.
    ///
    /// Without the fix, this is byte-for-byte the same shape as
    /// `body_dropped_before_end_of_stream_logs_dc` above (one frame, then
    /// `Pending` forever, then dropped) and asserted `DC 2` there on
    /// purpose. The only difference here is a `content-length: 2` response
    /// header that exactly matches the one frame -- which is precisely what
    /// tells `LoggingBody` the stream is actually, successfully done, not
    /// abandoned mid-flight.
    #[test]
    fn content_length_exhausted_with_no_further_poll_logs_no_flag_not_dc() {
        let capture = Arc::new(CaptureSink::default());
        let mut ctx = flags_ctx(&capture);
        ctx.response_headers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("2"),
        );
        let body = local_boxed(FrameThenPendingForever {
            frame: Some(Bytes::from_static(b"hi")),
        });
        let mut logging_body = LoggingBody::new(body, ctx);

        let waker = futures::task::noop_waker();
        let mut cx = TaskContext::from_waker(&waker);
        // The one real frame -- this exhausts `content-length: 2` exactly,
        // so the fix must finish() right here, inside this very poll.
        match Pin::new(&mut logging_body).poll_frame(&mut cx) {
            Poll::Ready(Some(Ok(_))) => {}
            other => panic!("expected the frame, got {other:?}"),
        }

        // The line must already be rendered -- not deferred to `Drop` -- and
        // it must carry no response flag, since nothing actually failed.
        //
        // Rust note: the lock is taken into a local and dropped BEFORE the
        // assertion, rather than inline inside `assert_eq!` -- a `MutexGuard`
        // produced as a temporary inside that macro lives until the end of
        // the whole statement (temporary lifetime extension), which is AFTER
        // the `panic!` a failing assertion raises. A panic while still
        // holding the guard poisons the mutex, and this test's own
        // `logging_body` unwinds (calling `Drop` -> `finish()` ->
        // `capture.0.lock()`) right after -- a second panic on a poisoned
        // lock during unwind is an abort, not a normal test failure. Binding
        // first sidesteps that entirely.
        let rendered_before_drop = capture.0.lock().unwrap().len();
        assert_eq!(
            rendered_before_drop, 1,
            "content-length exhaustion must finish() inside poll_frame, not wait for Drop"
        );

        // Never polled again after this (matches hyper's real write
        // dispatcher) and then dropped -- must NOT render a second line or
        // retroactively tag DC; `finish()` is already idempotent via
        // `ctx.take()`.
        drop(logging_body);

        let mut lines = capture.0.lock().unwrap();
        assert_eq!(
            lines.len(),
            1,
            "Drop after an already-clean finish must be a no-op, not a second line"
        );
        assert_eq!(
            lines.remove(0),
            "- 2",
            "a fully-delivered content-length response must log no flag, not DC"
        );
    }

    #[tokio::test]
    async fn clean_end_of_stream_sets_no_flag_and_does_not_warn() {
        // The negative control: without this, an implementation that always
        // set UC (or always warned) regardless of outcome would pass every
        // test above.
        let capture = Arc::new(CaptureSink::default());
        let counter = Arc::new(AtomicUsize::new(0));
        let guard = tracing::subscriber::set_default(WarnCounter(counter.clone()));

        let body = local_boxed(
            Full::new(Bytes::from_static(b"hi"))
                .map_err(|infallible: std::convert::Infallible| match infallible {}),
        );
        let logging_body = LoggingBody::new(body, flags_ctx(&capture));
        let collected = logging_body.collect().await.unwrap().to_bytes();
        assert_eq!(collected.as_ref(), b"hi");

        drop(guard);
        let mut lines = capture.0.lock().unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines.remove(0), "- 2", "no response flag on a clean end");
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "a clean end-of-stream must not warn"
        );
    }
}
