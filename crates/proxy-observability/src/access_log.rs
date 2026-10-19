//! The access-log format-string engine.
//!
//! Two halves, deliberately separated by cost:
//!
//! - [`parse_format`] runs once, at config-load time, turning an Envoy
//!   format string (e.g. `"[%START_TIME%] %REQ(:METHOD)%\n"`) into a
//!   [`FormatString`] — an ordered `Vec` of literal text and pre-resolved
//!   [`FormatOp`]s. An unknown `%OPERATOR%` is rejected here, not silently
//!   dropped or emitted as literal text (AGENTS.md invariant 1).
//! - [`render`] runs per request, on the hot path: it never re-parses
//!   anything, just walks the pre-built op list and writes into a `String`.
//!
//! Runtime sink wiring (actually calling `render` from the router/filter
//! manager and writing the result somewhere) is the sink's job, not this module's.

use std::fmt::Write as _;

use crate::flags::{render_flags, ResponseFlag};

/// A parsed access-log format string: literal text interleaved with
/// operator substitutions, in source order. Build once via [`parse_format`];
/// never re-parsed on the request path.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FormatString(pub Vec<FormatOp>);

/// One `%OPERATOR%` (or a literal run of text between operators) from a
/// parsed format string.
///
/// Rust note: "parse, don't validate." Every variant here is already valid, so
/// [`render`] only handles absent data (`-`), never a malformed format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatOp {
    /// Text copied through unchanged.
    Literal(String),
    /// `%START_TIME%` / `%START_TIME(fmt)%`. `None` = Envoy's default
    /// timestamp format.
    StartTime(Option<String>),
    /// `%REQ(X)%`, `%REQ(X?Y)%`, and the `:Z` truncation suffix.
    Req(HeaderSpec),
    /// `%RESP(X)%` / `%RESP(X?Y)%` / `:Z`.
    Resp(HeaderSpec),
    /// `%TRAILER(X)%` / `%TRAILER(X?Y)%` / `:Z`.
    Trailer(HeaderSpec),
    Protocol,
    ResponseCode,
    ResponseFlags,
    /// `%RESPONSE_CODE_DETAILS%` -- the free-text reason a response
    /// took the status it did (e.g. `cluster_not_found`, `no_healthy_upstream`,
    /// `cluster_not_warmed`). Distinguishes conditions that share one
    /// [`ResponseFlag`] short code -- see
    /// `proxy_http::stream_info::StreamInfo::response_code_details`'s doc for
    /// who populates it.
    ResponseCodeDetails,
    Duration,
    /// `%COMMON_DURATION(START:END[:PRECISION])%`: the time from one
    /// [`TimePoint`] to another. `-` when either point never happened or
    /// `END` precedes `START` (Envoy v1.38 `CommonDurationFormatter`).
    CommonDuration {
        start: TimePoint,
        end: TimePoint,
        precision: DurationPrecision,
    },
    BytesReceived,
    BytesSent,
    UpstreamHost,
    UpstreamCluster,
    DownstreamRemoteAddress,
    // No OTel GenAI semconv aliases for these operators. Semconv's
    // `gen_ai.usage.input_tokens` includes the cache buckets, while our
    // `input_tokens` excludes them. A plain alias would under-count billed
    // input under a standard-looking name, which is AGENTS.md invariant 1's
    // hazard in a naming disguise. A partial alias set would be worse.
    //
    /// `%LLM_INPUT_TOKENS%`.
    LlmInputTokens,
    /// `%LLM_CACHED_TOKENS%`.
    LlmCachedTokens,
    /// `%LLM_CACHE_CREATION_TOKENS%`.
    LlmCacheCreationTokens,
    /// `%LLM_OUTPUT_TOKENS%`.
    LlmOutputTokens,
    /// `%LLM_TOTAL_TOKENS%` -- the sum of all four buckets above.
    LlmTotalTokens,
    /// `%LLM_TTFT%` -- time-to-first-token, in milliseconds.
    LlmTtft,
    /// `%LLM_TPOT%` -- mean time per output token, in milliseconds:
    /// `(duration - ttft) / output_tokens`, computed at render time (see
    /// [`render_op`]'s `LlmTpot` arm for the full guard list).
    LlmTpot,
    /// `%LLM_MAX_STALL%` -- the largest gap between two consecutive
    /// response body chunks, in milliseconds. NOT the same thing as TPOT --
    /// see `LlmTokens`'s sibling field doc on `LogContext::llm_max_stall`.
    LlmMaxStall,
    /// `%LLM_RESPONSE_CHUNKS%` -- number of response body chunks
    /// observed for this stream.
    LlmResponseChunks,
    /// `%LLM_LIST_COST%`, in integer nanodollars.
    LlmListCost,
    LlmKeyId,
    LlmTenant,
    /// `%LLM_CREDENTIAL_SOURCE%` -- `platform` or `tenant`, whose credential
    /// the final attempt was sent with (ADR-0007). `-` when no attempt got
    /// as far as the credential step.
    LlmCredentialSource,
    LlmUserId,
    LlmRequestedModel,
    /// `%LLM_RESOLVED_MODEL%` -- the model a resolver chose when the
    /// requested model was `auto`. `-` when nothing was resolved.
    LlmResolvedModel,
    /// `%LLM_GUARDRAIL%` -- the `llmproxy.guardrail` outcome (`allowed`,
    /// `denied`, `error`, `timeout`, `over_limit`, `failure_mode_allowed`).
    /// `-` when no guardrail checked the request.
    LlmGuardrail,
    LlmSelectedModel,
    /// `%LLM_SERVED_MODEL%` -- the model the provider's response says it
    /// served, which can differ from the selected model (dated snapshots,
    /// provider-side fallback). `-` when the response named none.
    LlmServedModel,
    /// `%LLM_UPSTREAM_ID%` -- the provider's own id for the response
    /// (`chatcmpl-...`, `msg_...`, `resp_...`). `-` when the response carried
    /// none or it was over the size bound.
    LlmUpstreamId,
    /// `%LLM_UPSTREAM_USAGE%` -- the provider's `usage` object exactly as it
    /// sent it. A `json_format` field whose whole value is this operator
    /// embeds it as a JSON value (`null` when absent); anywhere else it is
    /// text, `-` when absent. Evidence only: it is never read for cost.
    LlmUpstreamUsage,
    /// `%LLM_USAGE_COMPLETENESS%` -- `complete` for a finished response,
    /// `partial` for a stream cut off before the provider's final usage (its
    /// tokens and cost are then estimates). `-` when no usage filter ran.
    LlmUsageCompleteness,
    /// `%LLM_COST_KIND%` -- `list` for a rate-card price of provider-reported
    /// usage, `estimate` when the usage it prices was estimated. `-` when
    /// there is no cost.
    LlmCostKind,
    LlmRateCardVersion,
}

/// The unit `%COMMON_DURATION%` renders in. Envoy truncates toward zero, so
/// 1.9 ms renders as `1` at `ms`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurationPrecision {
    /// `ms`, the default when the third argument is omitted.
    Milliseconds,
    /// `us`.
    Microseconds,
    /// `ns`.
    Nanoseconds,
}

/// Parse `%COMMON_DURATION%`'s `START:END[:PRECISION]` argument.
///
/// Envoy treats a name that is not one of its points as a custom time point a
/// filter may set by key. No filter here sets one, so such a name could only
/// ever render `-`; it is rejected instead, which also catches a misspelled
/// point (AGENTS.md invariant 1, `internal-docs/envoy-divergences.md`).
fn common_duration(args: Option<String>, input: &str) -> Result<FormatOp, FormatParseError> {
    let args = args.ok_or_else(|| {
        err(format!(
            "`%COMMON_DURATION%` requires `(START:END)` or `(START:END:PRECISION)` in format string `{input}`"
        ))
    })?;
    let parts: Vec<&str> = args.split(':').collect();
    if !(2..=3).contains(&parts.len()) {
        return Err(err(format!(
            "invalid `%COMMON_DURATION({args})%`: expected `START:END` or `START:END:PRECISION` in format string `{input}`"
        )));
    }
    let point = |name: &str| {
        TimePoint::from_name(name).ok_or_else(|| {
            let known: Vec<&str> = TimePoint::ALL.iter().map(|p| p.name()).collect();
            err(format!(
                "unknown `%COMMON_DURATION%` time point `{name}` (expected one of {}) in format string `{input}`",
                known.join(", ")
            ))
        })
    };
    let start = point(parts[0])?;
    let end = point(parts[1])?;
    let precision = match parts.get(2) {
        None | Some(&"ms") => DurationPrecision::Milliseconds,
        Some(&"us") => DurationPrecision::Microseconds,
        Some(&"ns") => DurationPrecision::Nanoseconds,
        Some(other) => {
            return Err(err(format!(
                "invalid `%COMMON_DURATION%` precision `{other}` (expected `ms`, `us` or `ns`) in format string `{input}`"
            )));
        }
    };
    Ok(FormatOp::CommonDuration {
        start,
        end,
        precision,
    })
}

/// The argument to `%REQ%`/`%RESP%`/`%TRAILER%`: a primary header name, an
/// optional `?FALLBACK` header tried when the primary is absent, and an
/// optional `:Z` max-length truncation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderSpec {
    pub primary: String,
    pub fallback: Option<String>,
    pub truncate: Option<usize>,
}

/// A malformed format string, with a human-readable reason. `proxy-config`'s
/// lowering pass wraps this into a `ConfigError` carrying the field's dotted
/// path (this crate doesn't know about that type — AGENTS.md invariant 2 keeps
/// proto/IR concerns out of the formatter).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct FormatParseError(pub String);

fn err(reason: impl Into<String>) -> FormatParseError {
    FormatParseError(reason.into())
}

/// Parse an Envoy access-log format string into an operator sequence.
///
/// Grammar per operator token: `%NAME%`, `%NAME(ARGS)%`, `%NAME:Z%`, or
/// `%NAME(ARGS):Z%`, where `ARGS` (when present) is scanned to its matching
/// `)` first — so a strftime pattern inside `%START_TIME(...)%` can itself
/// contain `%` without confusing the outer scan. A literal `%` is written as
/// `%%`.
pub fn parse_format(input: &str) -> Result<FormatString, FormatParseError> {
    let chars: Vec<char> = input.chars().collect();
    let mut ops = Vec::new();
    let mut literal = String::new();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] != '%' {
            literal.push(chars[i]);
            i += 1;
            continue;
        }
        if chars.get(i + 1) == Some(&'%') {
            literal.push('%');
            i += 2;
            continue;
        }

        // Operator name: uppercase ASCII letters and underscores.
        let name_start = i + 1;
        let mut j = name_start;
        while j < chars.len() && (chars[j].is_ascii_uppercase() || chars[j] == '_') {
            j += 1;
        }
        if j == name_start {
            return Err(err(format!(
                "unexpected `%` (not the start of a known operator) in format string `{input}`"
            )));
        }
        let name: String = chars[name_start..j].iter().collect();

        let mut args: Option<String> = None;
        if chars.get(j) == Some(&'(') {
            let open = j;
            let close = chars[open + 1..]
                .iter()
                .position(|&c| c == ')')
                .map(|p| open + 1 + p)
                .ok_or_else(|| {
                    err(format!(
                        "unterminated `(` for `%{name}(` in format string `{input}`"
                    ))
                })?;
            args = Some(chars[open + 1..close].iter().collect());
            j = close + 1;
        }

        let mut truncate: Option<usize> = None;
        if chars.get(j) == Some(&':') {
            let digits_start = j + 1;
            let mut k = digits_start;
            while k < chars.len() && chars[k].is_ascii_digit() {
                k += 1;
            }
            if k == digits_start {
                return Err(err(format!(
                    "expected digits after `:` in `%{name}` in format string `{input}`"
                )));
            }
            let n: String = chars[digits_start..k].iter().collect();
            truncate = Some(n.parse().map_err(|_| {
                err(format!(
                    "truncation length `{n}` out of range in `%{name}` in format string `{input}`"
                ))
            })?);
            j = k;
        }

        if chars.get(j) != Some(&'%') {
            return Err(err(format!(
                "unterminated operator `%{name}` (missing closing `%`) in format string `{input}`"
            )));
        }
        j += 1;

        if !literal.is_empty() {
            ops.push(FormatOp::Literal(std::mem::take(&mut literal)));
        }
        ops.push(build_op(&name, args, truncate, input)?);
        i = j;
    }

    if !literal.is_empty() {
        ops.push(FormatOp::Literal(literal));
    }
    Ok(FormatString(ops))
}

fn build_op(
    name: &str,
    args: Option<String>,
    truncate: Option<usize>,
    input: &str,
) -> Result<FormatOp, FormatParseError> {
    /// Operators that take neither `(ARGS)` nor `:Z` — anything else on them
    /// is a config error, not silently ignored (AGENTS.md invariant 1).
    fn bare(
        name: &str,
        args: Option<String>,
        truncate: Option<usize>,
        input: &str,
    ) -> Result<(), FormatParseError> {
        if args.is_some() {
            return Err(err(format!(
                "`%{name}%` does not take arguments in format string `{input}`"
            )));
        }
        if truncate.is_some() {
            return Err(err(format!(
                "`%{name}%` does not support `:Z` truncation in format string `{input}`"
            )));
        }
        Ok(())
    }

    fn header_spec(
        name: &str,
        args: Option<String>,
        truncate: Option<usize>,
        input: &str,
    ) -> Result<HeaderSpec, FormatParseError> {
        let args = args.ok_or_else(|| {
            err(format!(
                "`%{name}%` requires a header name, e.g. `%{name}(X)%` or `%{name}(X?Y)%`, in format string `{input}`"
            ))
        })?;
        let (primary, fallback) = match args.split_once('?') {
            Some((p, f)) => (p.to_string(), Some(f.to_string())),
            None => (args, None),
        };
        if primary.is_empty() {
            return Err(err(format!(
                "`%{name}(...)%` header name must not be empty in format string `{input}`"
            )));
        }
        Ok(HeaderSpec {
            primary,
            fallback,
            truncate,
        })
    }

    Ok(match name {
        "START_TIME" => {
            if truncate.is_some() {
                return Err(err(format!(
                    "`%START_TIME%` does not support `:Z` truncation in format string `{input}`"
                )));
            }
            // chrono stops writing at the first specifier it cannot format,
            // so an accepted bad pattern would log a truncated timestamp on
            // every request (AGENTS.md invariant 1,
            // `internal-docs/envoy-divergences.md`).
            if let Some(pattern) = &args {
                if chrono::format::StrftimeItems::new(pattern)
                    .any(|item| matches!(item, chrono::format::Item::Error))
                {
                    return Err(err(format!(
                        "`%START_TIME({pattern})%` is not a supported strftime pattern in format string `{input}`"
                    )));
                }
            }
            FormatOp::StartTime(args)
        }
        "REQ" => FormatOp::Req(header_spec(name, args, truncate, input)?),
        "RESP" => FormatOp::Resp(header_spec(name, args, truncate, input)?),
        "TRAILER" => FormatOp::Trailer(header_spec(name, args, truncate, input)?),
        "PROTOCOL" => {
            bare(name, args, truncate, input)?;
            FormatOp::Protocol
        }
        "RESPONSE_CODE" => {
            bare(name, args, truncate, input)?;
            FormatOp::ResponseCode
        }
        "RESPONSE_FLAGS" => {
            bare(name, args, truncate, input)?;
            FormatOp::ResponseFlags
        }
        "RESPONSE_CODE_DETAILS" => {
            bare(name, args, truncate, input)?;
            FormatOp::ResponseCodeDetails
        }
        "DURATION" => {
            bare(name, args, truncate, input)?;
            FormatOp::Duration
        }
        "COMMON_DURATION" => {
            if truncate.is_some() {
                return Err(err(format!(
                    "`%COMMON_DURATION%` does not support `:Z` truncation in format string `{input}`"
                )));
            }
            common_duration(args, input)?
        }
        "BYTES_RECEIVED" => {
            bare(name, args, truncate, input)?;
            FormatOp::BytesReceived
        }
        "BYTES_SENT" => {
            bare(name, args, truncate, input)?;
            FormatOp::BytesSent
        }
        "UPSTREAM_HOST" => {
            bare(name, args, truncate, input)?;
            FormatOp::UpstreamHost
        }
        "UPSTREAM_CLUSTER" => {
            bare(name, args, truncate, input)?;
            FormatOp::UpstreamCluster
        }
        "DOWNSTREAM_REMOTE_ADDRESS" => {
            bare(name, args, truncate, input)?;
            FormatOp::DownstreamRemoteAddress
        }
        "LLM_INPUT_TOKENS" => {
            bare(name, args, truncate, input)?;
            FormatOp::LlmInputTokens
        }
        "LLM_CACHED_TOKENS" => {
            bare(name, args, truncate, input)?;
            FormatOp::LlmCachedTokens
        }
        "LLM_CACHE_CREATION_TOKENS" => {
            bare(name, args, truncate, input)?;
            FormatOp::LlmCacheCreationTokens
        }
        "LLM_OUTPUT_TOKENS" => {
            bare(name, args, truncate, input)?;
            FormatOp::LlmOutputTokens
        }
        "LLM_TOTAL_TOKENS" => {
            bare(name, args, truncate, input)?;
            FormatOp::LlmTotalTokens
        }
        "LLM_TTFT" => {
            bare(name, args, truncate, input)?;
            FormatOp::LlmTtft
        }
        "LLM_TPOT" => {
            bare(name, args, truncate, input)?;
            FormatOp::LlmTpot
        }
        "LLM_MAX_STALL" => {
            bare(name, args, truncate, input)?;
            FormatOp::LlmMaxStall
        }
        "LLM_RESPONSE_CHUNKS" => {
            bare(name, args, truncate, input)?;
            FormatOp::LlmResponseChunks
        }
        "LLM_LIST_COST" => {
            bare(name, args, truncate, input)?;
            FormatOp::LlmListCost
        }
        "LLM_KEY_ID" => {
            bare(name, args, truncate, input)?;
            FormatOp::LlmKeyId
        }
        "LLM_TENANT" => {
            bare(name, args, truncate, input)?;
            FormatOp::LlmTenant
        }
        "LLM_CREDENTIAL_SOURCE" => {
            bare(name, args, truncate, input)?;
            FormatOp::LlmCredentialSource
        }
        "LLM_USER_ID" => {
            bare(name, args, truncate, input)?;
            FormatOp::LlmUserId
        }
        "LLM_REQUESTED_MODEL" => {
            bare(name, args, truncate, input)?;
            FormatOp::LlmRequestedModel
        }
        "LLM_RESOLVED_MODEL" => {
            bare(name, args, truncate, input)?;
            FormatOp::LlmResolvedModel
        }
        "LLM_GUARDRAIL" => {
            bare(name, args, truncate, input)?;
            FormatOp::LlmGuardrail
        }
        "LLM_SELECTED_MODEL" => {
            bare(name, args, truncate, input)?;
            FormatOp::LlmSelectedModel
        }
        "LLM_SERVED_MODEL" => {
            bare(name, args, truncate, input)?;
            FormatOp::LlmServedModel
        }
        "LLM_UPSTREAM_ID" => {
            bare(name, args, truncate, input)?;
            FormatOp::LlmUpstreamId
        }
        "LLM_UPSTREAM_USAGE" => {
            bare(name, args, truncate, input)?;
            FormatOp::LlmUpstreamUsage
        }
        "LLM_USAGE_COMPLETENESS" => {
            bare(name, args, truncate, input)?;
            FormatOp::LlmUsageCompleteness
        }
        "LLM_COST_KIND" => {
            bare(name, args, truncate, input)?;
            FormatOp::LlmCostKind
        }
        "LLM_RATE_CARD_VERSION" => {
            bare(name, args, truncate, input)?;
            FormatOp::LlmRateCardVersion
        }
        other => {
            return Err(err(format!(
                "unknown access-log format operator `%{other}%` in format string `{input}`"
            )));
        }
    })
}

// ------------------------------------------------------------- rendering --

/// Envoy's default `%START_TIME%` rendering: ISO-8601 with millisecond
/// precision and a literal `Z` (matches Envoy's `DEFAULT_TIME_FORMAT`,
/// `%Y-%m-%dT%H:%M:%E3SZ`, which chrono's strftime dialect spells with
/// `%.3f` instead of the abseil-specific `%E3S`).
const DEFAULT_START_TIME_FORMAT: &str = "%Y-%m-%dT%H:%M:%S%.3fZ";

/// Provider-reported token usage in the four billing buckets. It mirrors
/// `proxy_http::LlmTokenUsage` because `proxy-http` depends on this crate, not
/// the reverse (AGENTS.md invariant 2). The caller converts at the boundary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LlmTokens {
    pub input: u64,
    pub cached: u64,
    pub cache_creation: u64,
    pub output: u64,
}

impl LlmTokens {
    /// Total across all four buckets. Saturating: a billing count overflowing
    /// `u64` is not a case worth panicking the request over.
    pub fn total(&self) -> u64 {
        self.input
            .saturating_add(self.cached)
            .saturating_add(self.cache_creation)
            .saturating_add(self.output)
    }
}

/// One of Envoy's `%COMMON_DURATION%` time points (v1.38
/// `CommonDurationFormatter`). Each names a moment in one request's life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimePoint {
    /// `DS_RX_BEG`: the stream started (Envoy's `startTimeMonotonic`).
    DsRxBeg,
    /// `DS_RX_END`: the last downstream request byte was received.
    DsRxEnd,
    /// `US_CX_BEG`: the upstream TCP connect began.
    UsCxBeg,
    /// `US_CX_END`: the upstream TCP connect completed.
    UsCxEnd,
    /// `US_HS_END`: the upstream TLS handshake completed. Never set for a
    /// plaintext upstream.
    UsHsEnd,
    /// `US_TX_BEG`: the request head was handed to the upstream codec.
    UsTxBeg,
    /// `US_TX_END`: the last request body byte was handed to the upstream codec.
    UsTxEnd,
    /// `US_RX_BEG`: the upstream response head was received.
    UsRxBeg,
    /// `US_RX_BODY_BEG`: the first upstream response body byte was received.
    UsRxBodyBeg,
    /// `US_RX_END`: the last upstream response byte was received.
    UsRxEnd,
    /// `DS_TX_BEG`: the response head was handed to the downstream codec.
    DsTxBeg,
    /// `DS_TX_END`: the last response byte was handed to the downstream codec.
    DsTxEnd,
}

impl TimePoint {
    /// Every point, in [`TimePoints`] storage order.
    pub const ALL: [TimePoint; 12] = [
        TimePoint::DsRxBeg,
        TimePoint::DsRxEnd,
        TimePoint::UsCxBeg,
        TimePoint::UsCxEnd,
        TimePoint::UsHsEnd,
        TimePoint::UsTxBeg,
        TimePoint::UsTxEnd,
        TimePoint::UsRxBeg,
        TimePoint::UsRxBodyBeg,
        TimePoint::UsRxEnd,
        TimePoint::DsTxBeg,
        TimePoint::DsTxEnd,
    ];

    /// The case-sensitive name Envoy's format strings use.
    pub const fn name(self) -> &'static str {
        match self {
            TimePoint::DsRxBeg => "DS_RX_BEG",
            TimePoint::DsRxEnd => "DS_RX_END",
            TimePoint::UsCxBeg => "US_CX_BEG",
            TimePoint::UsCxEnd => "US_CX_END",
            TimePoint::UsHsEnd => "US_HS_END",
            TimePoint::UsTxBeg => "US_TX_BEG",
            TimePoint::UsTxEnd => "US_TX_END",
            TimePoint::UsRxBeg => "US_RX_BEG",
            TimePoint::UsRxBodyBeg => "US_RX_BODY_BEG",
            TimePoint::UsRxEnd => "US_RX_END",
            TimePoint::DsTxBeg => "DS_TX_BEG",
            TimePoint::DsTxEnd => "DS_TX_END",
        }
    }

    /// The point a format string names, `None` for any other name.
    pub fn from_name(name: &str) -> Option<TimePoint> {
        TimePoint::ALL.into_iter().find(|p| p.name() == name)
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// The monotonic instant of each [`TimePoint`] a request reached. A point
/// that never happened stays `None` and renders as `-`.
///
/// Rust note: a fixed array indexed by the enum's discriminant, not a map, so
/// the type is `Copy` and building a [`LogContext`] stays allocation-free.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TimePoints([Option<std::time::Instant>; 12]);

impl TimePoints {
    pub fn get(&self, point: TimePoint) -> Option<std::time::Instant> {
        self.0[point.index()]
    }

    pub fn set(&mut self, point: TimePoint, at: Option<std::time::Instant>) {
        self.0[point.index()] = at;
    }
}

/// Everything a request or stream knows when it is logged. The caller builds it
/// and passes it to [`render`].
///
/// Rust note: `'a` ties the borrowed fields to the caller's frame. The context
/// owns nothing, so building one does not allocate.
pub struct LogContext<'a> {
    pub start_time: std::time::SystemTime,
    pub request_headers: &'a http::HeaderMap,
    pub response_headers: &'a http::HeaderMap,
    pub response_trailers: &'a http::HeaderMap,
    pub protocol: Option<&'a str>,
    pub response_code: Option<u16>,
    /// Every flag that fired, in the order they were recorded. Empty = none
    /// fired, rendered as `-` (matching a non-firing scalar operator).
    pub response_flags: &'a [ResponseFlag],
    pub duration: Option<std::time::Duration>,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub upstream_host: Option<&'a str>,
    pub upstream_cluster: Option<&'a str>,
    pub downstream_remote_address: Option<&'a str>,
    /// `%RESPONSE_CODE_DETAILS%` -- `None` when whoever finalized the
    /// response never set one (most successful responses today), rendered as
    /// `-` like every other absent [`Option`] field in this struct.
    pub response_code_details: Option<&'a str>,
    /// Provider-reported token usage. `None` when the response
    /// carried none -- a non-LLM route, or a provider that reported nothing.
    pub llm_tokens: Option<LlmTokens>,
    /// Time-to-first-token -- response headers to first body byte.
    pub llm_ttft: Option<std::time::Duration>,
    /// The largest gap between two consecutive response body chunks
    /// -- the tail of the TPOT distribution, NOT the mean (`%LLM_TPOT%`
    /// below computes the mean separately). `None` for a non-streamed
    /// response, or one that never populated `StreamInfo::llm`.
    pub llm_max_stall: Option<std::time::Duration>,
    /// Number of response body chunks observed for this stream.
    pub llm_response_chunks: u64,
    /// The request-time list price. `None` is unpriced/unknown, not zero.
    pub llm_list_cost_nanodollars: Option<u64>,
    /// Usage attribution; absent identities and unpriced cards remain absent.
    pub llm_key_id: Option<&'a str>,
    pub llm_tenant: Option<&'a str>,
    /// `CredentialSource::as_str()` of the final attempt, `None` when the
    /// request never reached the credential step.
    pub llm_credential_source: Option<&'a str>,
    pub llm_user_id: Option<&'a str>,
    pub llm_requested_model: Option<&'a str>,
    pub llm_resolved_model: Option<&'a str>,
    /// The guardrail outcome; `None` when no guardrail checked the request.
    pub llm_guardrail: Option<&'a str>,
    pub llm_selected_model: Option<&'a str>,
    /// The model the provider reported serving; `None` when the response named none.
    pub llm_served_model: Option<&'a str>,
    /// The provider's response id; `None` when it named none.
    pub llm_upstream_id: Option<&'a str>,
    /// The provider's `usage` object as JSON text, exactly as sent.
    pub llm_upstream_usage: Option<&'a str>,
    /// `complete` / `partial`; `None` when no usage filter ran.
    pub llm_usage_completeness: Option<&'a str>,
    /// `list` / `estimate`; `None` when there is no cost.
    pub llm_cost_kind: Option<&'a str>,
    pub llm_rate_card_version: Option<&'a str>,

    /// The request's `%COMMON_DURATION%` time points.
    pub time_points: TimePoints,

    /// Envoy request pseudo-header `:method` -- e.g. `GET`. These four fields
    /// exist because `:method`/`:path`/`:authority`/`:scheme` are not legal
    /// `http::HeaderName`s (a colon isn't a valid HTTP field-name character),
    /// so they can't live in `request_headers` -- see `header_lookup`'s doc.
    pub request_method: Option<&'a str>,
    /// Envoy request pseudo-header `:path` -- e.g. `/v1/chat/completions`.
    pub request_path: Option<&'a str>,
    /// Envoy request pseudo-header `:authority` -- the request's `Host`.
    pub request_authority: Option<&'a str>,
    /// Envoy request pseudo-header `:scheme` -- e.g. `https`.
    pub request_scheme: Option<&'a str>,
}

/// Render a parsed format string against a request's context. Allocation is
/// limited to the output `String` and any truncated header values.
pub fn render(fmt: &FormatString, ctx: &LogContext<'_>) -> String {
    let mut out = String::new();
    render_into(fmt, ctx, &mut out);
    out
}

/// [`render`], appending to `out`, so a caller that renders many format
/// strings per line (`json_format`) can reuse one buffer.
pub fn render_into(fmt: &FormatString, ctx: &LogContext<'_>, out: &mut String) {
    for op in &fmt.0 {
        render_op(op, ctx, out);
    }
}

/// `%START_TIME%` in [`DEFAULT_START_TIME_FORMAT`], without chrono's strftime,
/// which parses the pattern again on every call. Returns `false`, and the
/// caller falls back to chrono, where the output could differ: a year outside
/// 0 to 9999 (chrono's `%Y` adds a sign) or a leap second (`%S` renders 60).
fn write_default_start_time(dt: &chrono::DateTime<chrono::Utc>, out: &mut String) -> bool {
    use chrono::{Datelike as _, Timelike as _};
    if !(0..=9999).contains(&dt.year()) || dt.nanosecond() >= 1_000_000_000 {
        return false;
    }
    // `%.3f` truncates to milliseconds.
    let millis = dt.nanosecond() / 1_000_000;
    let _ = write!(
        out,
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
    );
    true
}

fn render_op(op: &FormatOp, ctx: &LogContext<'_>, out: &mut String) {
    match op {
        FormatOp::Literal(s) => out.push_str(s),
        FormatOp::StartTime(fmt) => {
            let dt: chrono::DateTime<chrono::Utc> = ctx.start_time.into();
            let pattern = fmt.as_deref().unwrap_or(DEFAULT_START_TIME_FORMAT);
            if pattern != DEFAULT_START_TIME_FORMAT || !write_default_start_time(&dt, out) {
                let _ = write!(out, "{}", dt.format(pattern));
            }
        }
        FormatOp::Req(spec) => render_req(ctx, spec, out),
        FormatOp::Resp(spec) => render_resp(ctx, spec, out),
        FormatOp::Trailer(spec) => render_header(ctx.response_trailers, spec, out),
        FormatOp::Protocol => out.push_str(ctx.protocol.unwrap_or("-")),
        FormatOp::ResponseCode => match ctx.response_code {
            Some(c) => {
                let _ = write!(out, "{c}");
            }
            None => out.push('-'),
        },
        FormatOp::ResponseFlags => {
            if ctx.response_flags.is_empty() {
                out.push('-');
            } else {
                out.push_str(&render_flags(ctx.response_flags));
            }
        }
        FormatOp::Duration => match ctx.duration {
            Some(d) => {
                let _ = write!(out, "{}", d.as_millis());
            }
            None => out.push('-'),
        },
        FormatOp::CommonDuration {
            start,
            end,
            precision,
        } => {
            let span = ctx
                .time_points
                .get(*start)
                .zip(ctx.time_points.get(*end))
                .and_then(|(start, end)| end.checked_duration_since(start));
            match span {
                Some(d) => {
                    let count = match precision {
                        DurationPrecision::Milliseconds => d.as_millis(),
                        DurationPrecision::Microseconds => d.as_micros(),
                        DurationPrecision::Nanoseconds => d.as_nanos(),
                    };
                    let _ = write!(out, "{count}");
                }
                None => out.push('-'),
            }
        }
        FormatOp::BytesReceived => {
            let _ = write!(out, "{}", ctx.bytes_received);
        }
        FormatOp::BytesSent => {
            let _ = write!(out, "{}", ctx.bytes_sent);
        }
        FormatOp::UpstreamHost => out.push_str(ctx.upstream_host.unwrap_or("-")),
        FormatOp::UpstreamCluster => out.push_str(ctx.upstream_cluster.unwrap_or("-")),
        FormatOp::DownstreamRemoteAddress => {
            out.push_str(ctx.downstream_remote_address.unwrap_or("-"))
        }
        FormatOp::ResponseCodeDetails => out.push_str(ctx.response_code_details.unwrap_or("-")),
        // These six feed billing, so absent usage must render `-`,
        // never a confident-looking `0` -- `None` means "the provider told
        // us nothing", not "zero tokens were used".
        FormatOp::LlmInputTokens => match ctx.llm_tokens {
            Some(t) => {
                let _ = write!(out, "{}", t.input);
            }
            None => out.push('-'),
        },
        FormatOp::LlmCachedTokens => match ctx.llm_tokens {
            Some(t) => {
                let _ = write!(out, "{}", t.cached);
            }
            None => out.push('-'),
        },
        FormatOp::LlmCacheCreationTokens => match ctx.llm_tokens {
            Some(t) => {
                let _ = write!(out, "{}", t.cache_creation);
            }
            None => out.push('-'),
        },
        FormatOp::LlmOutputTokens => match ctx.llm_tokens {
            Some(t) => {
                let _ = write!(out, "{}", t.output);
            }
            None => out.push('-'),
        },
        FormatOp::LlmTotalTokens => match ctx.llm_tokens {
            Some(t) => {
                let _ = write!(out, "{}", t.total());
            }
            None => out.push('-'),
        },
        FormatOp::LlmTtft => match ctx.llm_ttft {
            Some(d) => {
                let _ = write!(out, "{}", d.as_millis());
            }
            None => out.push('-'),
        },
        // Mean time per output token: `(duration - ttft) / output_tokens`. Renders
        // `-` when usage, TTFT or duration is missing, when there are no output
        // tokens, or when duration < ttft (clock skew).
        // Rust note: `checked_sub` returns `None` on underflow, where `-` panics.
        FormatOp::LlmTpot => {
            let tpot = (|| {
                let output_tokens = ctx.llm_tokens?.output;
                if output_tokens == 0 {
                    return None;
                }
                let ttft = ctx.llm_ttft?;
                let duration = ctx.duration?;
                let numerator = duration.checked_sub(ttft)?;
                // Divide in microseconds. Millisecond division would render 0 for
                // fast providers (1000+ tok/s), which reads as a broken stream.
                //
                // Rust note: integer arithmetic, not `f64`, so output is
                // reproducible and can be diffed in tests.
                Some(numerator.as_micros() / u128::from(output_tokens))
            })();
            match tpot {
                Some(us_per_token) => {
                    let _ = write!(out, "{}.{:03}", us_per_token / 1000, us_per_token % 1000);
                }
                None => out.push('-'),
            }
        }
        FormatOp::LlmMaxStall => match ctx.llm_max_stall {
            Some(d) => {
                let _ = write!(out, "{}", d.as_millis());
            }
            None => out.push('-'),
        },
        FormatOp::LlmResponseChunks => {
            let _ = write!(out, "{}", ctx.llm_response_chunks);
        }
        FormatOp::LlmKeyId => out.push_str(ctx.llm_key_id.unwrap_or("-")),
        FormatOp::LlmTenant => out.push_str(ctx.llm_tenant.unwrap_or("-")),
        FormatOp::LlmCredentialSource => {
            out.push_str(ctx.llm_credential_source.unwrap_or("-"));
        }
        FormatOp::LlmUserId => out.push_str(ctx.llm_user_id.unwrap_or("-")),
        FormatOp::LlmRequestedModel => out.push_str(ctx.llm_requested_model.unwrap_or("-")),
        FormatOp::LlmResolvedModel => out.push_str(ctx.llm_resolved_model.unwrap_or("-")),
        FormatOp::LlmGuardrail => out.push_str(ctx.llm_guardrail.unwrap_or("-")),
        FormatOp::LlmSelectedModel => out.push_str(ctx.llm_selected_model.unwrap_or("-")),
        FormatOp::LlmServedModel => out.push_str(ctx.llm_served_model.unwrap_or("-")),
        FormatOp::LlmUpstreamId => out.push_str(ctx.llm_upstream_id.unwrap_or("-")),
        FormatOp::LlmUpstreamUsage => out.push_str(ctx.llm_upstream_usage.unwrap_or("-")),
        FormatOp::LlmUsageCompleteness => out.push_str(ctx.llm_usage_completeness.unwrap_or("-")),
        FormatOp::LlmCostKind => out.push_str(ctx.llm_cost_kind.unwrap_or("-")),
        FormatOp::LlmRateCardVersion => out.push_str(ctx.llm_rate_card_version.unwrap_or("-")),
        FormatOp::LlmListCost => match ctx.llm_list_cost_nanodollars {
            Some(cost) => {
                let _ = write!(out, "{cost}");
            }
            None => out.push('-'),
        },
    }
}

/// Shared core of `%REQ%`/`%RESP%`/`%TRAILER%`: resolve the primary name, then
/// the fallback, then apply `:Z` truncation, or render `-`. Each caller supplies
/// `resolve`, the only part that differs between them.
///
/// Rust note: `resolve` returns `Cow` so a header lookup can borrow from the
/// `HeaderMap` while `:status` returns an owned, formatted `String`.
fn render_named<'a, F>(spec: &HeaderSpec, mut resolve: F, out: &mut String)
where
    F: FnMut(&str) -> Option<std::borrow::Cow<'a, str>>,
{
    let mut value = resolve(&spec.primary);
    if value.is_none() {
        if let Some(fallback) = &spec.fallback {
            value = resolve(fallback);
        }
    }
    match value {
        Some(v) => match spec.truncate {
            Some(n) if v.chars().count() > n => out.extend(v.chars().take(n)),
            _ => out.push_str(&v),
        },
        None => out.push('-'),
    }
}

fn render_header(map: &http::HeaderMap, spec: &HeaderSpec, out: &mut String) {
    render_named(
        spec,
        |name| header_lookup(map, name).map(std::borrow::Cow::Borrowed),
        out,
    );
}

/// `%REQ(X)%`/`%REQ(X?Y)%`. A `:`-prefixed name is one of Envoy's four request
/// pseudo-headers and resolves against the typed [`LogContext`] fields. Any
/// other pseudo-name resolves to `None`. AGENTS.md invariant 1 does not apply
/// here, since the format was validated at parse time and this is just absent
/// data. Other names use [`header_lookup`].
fn render_req(ctx: &LogContext<'_>, spec: &HeaderSpec, out: &mut String) {
    render_named(
        spec,
        |name| resolve_req_pseudo(ctx, name).map(std::borrow::Cow::Borrowed),
        out,
    );
}

fn resolve_req_pseudo<'a>(ctx: &LogContext<'a>, name: &str) -> Option<&'a str> {
    if let Some(pseudo) = name.strip_prefix(':') {
        return match pseudo.to_ascii_lowercase().as_str() {
            "method" => ctx.request_method,
            "path" => ctx.request_path,
            "authority" => ctx.request_authority,
            "scheme" => ctx.request_scheme,
            _ => None,
        };
    }
    let value = header_lookup(ctx.request_headers, name)?;
    if is_credential_header(name) {
        return Some(REDACTED);
    }
    Some(value)
}

/// What `%REQ(X)%` renders for a credential header that is present: its
/// presence, never its value.
const REDACTED: &str = "[REDACTED]";

/// Request headers that carry a credential. These render as presence only, so a
/// format naming `%REQ(authorization)%` cannot write a key to the log. Envoy
/// renders them verbatim. This departure is in
/// `internal-docs/envoy-divergences.md`.
const CREDENTIAL_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
    "cookie",
];

fn is_credential_header(name: &str) -> bool {
    CREDENTIAL_HEADERS
        .iter()
        .any(|credential| credential.eq_ignore_ascii_case(name))
}

/// `%RESP(X)%`/`%RESP(X?Y)%`: only `:status` is a recognized response
/// pseudo-header (resolving to `ctx.response_code`, formatted); any other
/// pseudo-name resolves to `None`. `%TRAILER%` does NOT go through this --
/// trailers have no pseudo-headers, so `FormatOp::Trailer` still renders via
/// plain [`render_header`].
fn render_resp(ctx: &LogContext<'_>, spec: &HeaderSpec, out: &mut String) {
    render_named(spec, |name| resolve_resp_pseudo(ctx, name), out);
}

fn resolve_resp_pseudo<'a>(ctx: &LogContext<'a>, name: &str) -> Option<std::borrow::Cow<'a, str>> {
    if let Some(pseudo) = name.strip_prefix(':') {
        return match pseudo.to_ascii_lowercase().as_str() {
            "status" => ctx
                .response_code
                .map(|c| std::borrow::Cow::Owned(c.to_string())),
            _ => None,
        };
    }
    header_lookup(ctx.response_headers, name).map(std::borrow::Cow::Borrowed)
}

/// Header lookup by name. Pseudo-headers such as `:method` are not valid
/// `http::HeaderName`s, so [`render_req`] and [`render_resp`] resolve them
/// first. A malformed name returns `None` rather than panicking.
fn header_lookup<'a>(map: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
    let header_name = http::HeaderName::from_bytes(name.to_ascii_lowercase().as_bytes()).ok()?;
    map.get(header_name)?.to_str().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> FormatString {
        parse_format(s).unwrap_or_else(|e| panic!("parse `{s}` failed: {e}"))
    }

    #[test]
    fn literal_only() {
        assert_eq!(parse("hello").0, vec![FormatOp::Literal("hello".into())]);
    }

    #[test]
    fn escaped_percent() {
        assert_eq!(parse("100%%").0, vec![FormatOp::Literal("100%".into())]);
    }

    #[test]
    fn start_time_bare_and_with_format() {
        assert_eq!(parse("%START_TIME%").0, vec![FormatOp::StartTime(None)]);
        assert_eq!(
            parse("%START_TIME(%s)%").0,
            vec![FormatOp::StartTime(Some("%s".into()))]
        );
        assert_eq!(
            parse("%START_TIME(%Y-%m-%dT%H:%M:%S.%3fZ)%").0,
            vec![FormatOp::StartTime(Some("%Y-%m-%dT%H:%M:%S.%3fZ".into()))]
        );
    }

    /// Found by the `access_log_format` fuzz target: these patterns used to
    /// load, then render a timestamp cut off at the bad specifier.
    #[test]
    fn start_time_pattern_chrono_cannot_render_is_refused() {
        for pattern in [
            "%Y-%m-%dT%H:%3.M:f%%SZ",
            // Envoy's (abseil) sub-second seconds; chrono has no `%E`.
            "%Y-%m-%dT%H:%M:%E3SZ",
            "%Q",
        ] {
            let src = format!("[%START_TIME({pattern})%]");
            let e = parse_format(&src).unwrap_err();
            assert!(
                e.0.contains("not a supported strftime pattern"),
                "{src}: {e}"
            );
        }
    }

    #[test]
    fn req_plain_fallback_and_truncate() {
        assert_eq!(
            parse("%REQ(:METHOD)%").0,
            vec![FormatOp::Req(HeaderSpec {
                primary: ":METHOD".into(),
                fallback: None,
                truncate: None
            })]
        );
        assert_eq!(
            parse("%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%").0,
            vec![FormatOp::Req(HeaderSpec {
                primary: "X-ENVOY-ORIGINAL-PATH".into(),
                fallback: Some(":PATH".into()),
                truncate: None
            })]
        );
        assert_eq!(
            parse("%REQ(X?Y):10%").0,
            vec![FormatOp::Req(HeaderSpec {
                primary: "X".into(),
                fallback: Some("Y".into()),
                truncate: Some(10)
            })]
        );
    }

    #[test]
    fn resp_and_trailer() {
        assert_eq!(
            parse("%RESP(X)%").0,
            vec![FormatOp::Resp(HeaderSpec {
                primary: "X".into(),
                fallback: None,
                truncate: None
            })]
        );
        assert_eq!(
            parse("%TRAILER(grpc-status)%").0,
            vec![FormatOp::Trailer(HeaderSpec {
                primary: "grpc-status".into(),
                fallback: None,
                truncate: None
            })]
        );
    }

    #[test]
    fn every_scalar_operator_parses() {
        for (src, expect) in [
            ("%PROTOCOL%", FormatOp::Protocol),
            ("%RESPONSE_CODE%", FormatOp::ResponseCode),
            ("%RESPONSE_FLAGS%", FormatOp::ResponseFlags),
            ("%RESPONSE_CODE_DETAILS%", FormatOp::ResponseCodeDetails),
            ("%DURATION%", FormatOp::Duration),
            ("%BYTES_RECEIVED%", FormatOp::BytesReceived),
            ("%BYTES_SENT%", FormatOp::BytesSent),
            ("%UPSTREAM_HOST%", FormatOp::UpstreamHost),
            ("%UPSTREAM_CLUSTER%", FormatOp::UpstreamCluster),
            (
                "%DOWNSTREAM_REMOTE_ADDRESS%",
                FormatOp::DownstreamRemoteAddress,
            ),
            ("%LLM_INPUT_TOKENS%", FormatOp::LlmInputTokens),
            ("%LLM_CACHED_TOKENS%", FormatOp::LlmCachedTokens),
            (
                "%LLM_CACHE_CREATION_TOKENS%",
                FormatOp::LlmCacheCreationTokens,
            ),
            ("%LLM_OUTPUT_TOKENS%", FormatOp::LlmOutputTokens),
            ("%LLM_TOTAL_TOKENS%", FormatOp::LlmTotalTokens),
            ("%LLM_TTFT%", FormatOp::LlmTtft),
            ("%LLM_TPOT%", FormatOp::LlmTpot),
            ("%LLM_MAX_STALL%", FormatOp::LlmMaxStall),
            ("%LLM_RESPONSE_CHUNKS%", FormatOp::LlmResponseChunks),
        ] {
            assert_eq!(parse(src).0, vec![expect], "operator {src}");
        }
    }

    #[test]
    fn unknown_operator_is_rejected() {
        let e = parse_format("%NOT_A_REAL_OPERATOR%").unwrap_err();
        assert!(e.0.contains("NOT_A_REAL_OPERATOR"), "{e}");
    }

    #[test]
    fn bare_operator_rejects_arguments_and_truncation() {
        assert!(parse_format("%PROTOCOL(X)%").is_err());
        assert!(parse_format("%PROTOCOL:5%").is_err());
    }

    #[test]
    fn req_without_args_is_rejected() {
        assert!(parse_format("%REQ%").is_err());
    }

    #[test]
    fn unterminated_operator_is_rejected() {
        assert!(parse_format("%REQ(X)").is_err());
        assert!(parse_format("%REQ(X").is_err());
        assert!(parse_format("%PROTOCOL").is_err());
    }

    #[test]
    fn mixed_literal_and_operators_roundtrip_structure() {
        let fs = parse("[%START_TIME%] \"%REQ(:METHOD)%\"\n");
        assert_eq!(
            fs.0,
            vec![
                FormatOp::Literal("[".into()),
                FormatOp::StartTime(None),
                FormatOp::Literal("] \"".into()),
                FormatOp::Req(HeaderSpec {
                    primary: ":METHOD".into(),
                    fallback: None,
                    truncate: None
                }),
                FormatOp::Literal("\"\n".into()),
            ]
        );
    }

    // ------------------------------------------------------------ render --

    fn ctx<'a>(
        req: &'a http::HeaderMap,
        resp: &'a http::HeaderMap,
        trailers: &'a http::HeaderMap,
        flags: &'a [ResponseFlag],
    ) -> LogContext<'a> {
        LogContext {
            start_time: std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(0),
            request_headers: req,
            response_headers: resp,
            response_trailers: trailers,
            protocol: Some("HTTP/1.1"),
            response_code: Some(200),
            response_flags: flags,
            duration: Some(std::time::Duration::from_millis(42)),
            bytes_received: 10,
            bytes_sent: 20,
            upstream_host: Some("10.0.0.1:8080"),
            upstream_cluster: Some("my_cluster"),
            downstream_remote_address: Some("127.0.0.1:1234"),
            response_code_details: None,
            llm_tokens: None,
            llm_ttft: None,
            llm_max_stall: None,
            llm_response_chunks: 0,
            llm_list_cost_nanodollars: None,
            llm_key_id: None,
            llm_tenant: None,
            llm_credential_source: None,
            llm_user_id: None,
            llm_requested_model: None,
            llm_resolved_model: None,
            llm_guardrail: None,
            llm_selected_model: None,
            llm_served_model: None,
            llm_upstream_id: None,
            llm_upstream_usage: None,
            llm_usage_completeness: None,
            llm_cost_kind: None,
            llm_rate_card_version: None,

            request_method: Some("POST"),
            request_path: Some("/v1/chat/completions"),
            request_authority: Some("api.example.com"),
            request_scheme: Some("https"),
            time_points: TimePoints::default(),
        }
    }

    #[test]
    fn renders_usage_attribution_and_absence() {
        let empty = http::HeaderMap::new();
        let mut c = ctx(&empty, &empty, &empty, &[]);
        let fs = parse("%LLM_KEY_ID% %LLM_TENANT% %LLM_USER_ID% %LLM_REQUESTED_MODEL% %LLM_SELECTED_MODEL% %LLM_RATE_CARD_VERSION%");
        assert_eq!(render(&fs, &c), "- - - - - -");
        c.llm_key_id = Some("stable-key");
        c.llm_tenant = Some("tenant-a");
        c.llm_requested_model = Some("alias");
        c.llm_selected_model = Some("provider-model");
        c.llm_rate_card_version = Some("card-v2");
        assert_eq!(
            render(&fs, &c),
            "stable-key tenant-a - alias provider-model card-v2"
        );
        assert!(parse_format("%LLM_KEY_ID(secret)%").is_err());
    }

    #[test]
    fn renders_the_resolved_model_and_dash_when_nothing_was_resolved() {
        let empty = http::HeaderMap::new();
        let mut c = ctx(&empty, &empty, &empty, &[]);
        let fs = parse("%LLM_REQUESTED_MODEL% %LLM_RESOLVED_MODEL% %LLM_SELECTED_MODEL%");
        c.llm_requested_model = Some("gpt-4o");
        c.llm_selected_model = Some("gpt-4o");
        assert_eq!(render(&fs, &c), "gpt-4o - gpt-4o");
        c.llm_requested_model = Some("auto");
        c.llm_resolved_model = Some("fast");
        c.llm_selected_model = Some("provider-fast-v2");
        assert_eq!(render(&fs, &c), "auto fast provider-fast-v2");
        assert!(parse_format("%LLM_RESOLVED_MODEL(x)%").is_err());
    }

    #[test]
    fn renders_the_guardrail_outcome_and_dash_when_unchecked() {
        let empty = http::HeaderMap::new();
        let mut c = ctx(&empty, &empty, &empty, &[]);
        let fs = parse("%LLM_GUARDRAIL%");
        assert_eq!(render(&fs, &c), "-");
        c.llm_guardrail = Some("denied");
        assert_eq!(render(&fs, &c), "denied");
        assert!(parse_format("%LLM_GUARDRAIL(x)%").is_err());
    }

    #[test]
    fn renders_credential_source_and_dash_when_no_attempt_reached_it() {
        let empty = http::HeaderMap::new();
        let mut c = ctx(&empty, &empty, &empty, &[]);
        let fs = parse("%LLM_CREDENTIAL_SOURCE% %LLM_TENANT%");
        assert_eq!(render(&fs, &c), "- -");
        c.llm_credential_source = Some("tenant");
        c.llm_tenant = Some("tenant-a");
        assert_eq!(render(&fs, &c), "tenant tenant-a");
        c.llm_credential_source = Some("platform");
        assert_eq!(render(&fs, &c), "platform tenant-a");
        assert!(parse_format("%LLM_CREDENTIAL_SOURCE(x)%").is_err());
    }

    #[test]
    fn renders_served_model_and_dash_when_the_response_named_none() {
        let empty = http::HeaderMap::new();
        let mut c = ctx(&empty, &empty, &empty, &[]);
        let fs = parse("%LLM_SELECTED_MODEL% %LLM_SERVED_MODEL%");
        c.llm_selected_model = Some("gpt-4o-mini");
        assert_eq!(render(&fs, &c), "gpt-4o-mini -");
        c.llm_served_model = Some("gpt-4o-mini-2024-07-18");
        assert_eq!(render(&fs, &c), "gpt-4o-mini gpt-4o-mini-2024-07-18");
        assert!(parse_format("%LLM_SERVED_MODEL(x)%").is_err());
    }

    #[test]
    fn renders_upstream_id_and_usage_text_and_dash_when_absent() {
        let empty = http::HeaderMap::new();
        let mut c = ctx(&empty, &empty, &empty, &[]);
        let fs = parse("%LLM_UPSTREAM_ID% %LLM_UPSTREAM_USAGE%");
        assert_eq!(render(&fs, &c), "- -");
        c.llm_upstream_id = Some("chatcmpl-abc");
        c.llm_upstream_usage = Some(r#"{"prompt_tokens":7}"#);
        assert_eq!(render(&fs, &c), r#"chatcmpl-abc {"prompt_tokens":7}"#);
        assert!(parse_format("%LLM_UPSTREAM_ID(x)%").is_err());
        assert!(parse_format("%LLM_UPSTREAM_USAGE:5%").is_err());
    }

    #[test]
    fn renders_completeness_and_cost_kind_and_dash_when_absent() {
        let empty = http::HeaderMap::new();
        let mut c = ctx(&empty, &empty, &empty, &[]);
        let fs = parse("%LLM_USAGE_COMPLETENESS% %LLM_COST_KIND%");
        assert_eq!(render(&fs, &c), "- -");
        c.llm_usage_completeness = Some("partial");
        c.llm_cost_kind = Some("estimate");
        assert_eq!(render(&fs, &c), "partial estimate");
        assert!(parse_format("%LLM_COST_KIND(x)%").is_err());
    }

    #[test]
    fn renders_scalars() {
        let empty = http::HeaderMap::new();
        let c = ctx(&empty, &empty, &empty, &[]);
        let fs = parse(
            "%PROTOCOL% %RESPONSE_CODE% %DURATION% %BYTES_RECEIVED% %BYTES_SENT% %UPSTREAM_HOST% %UPSTREAM_CLUSTER% %DOWNSTREAM_REMOTE_ADDRESS%",
        );
        assert_eq!(
            render(&fs, &c),
            "HTTP/1.1 200 42 10 20 10.0.0.1:8080 my_cluster 127.0.0.1:1234"
        );
    }

    #[test]
    fn absent_values_render_dash() {
        let empty = http::HeaderMap::new();
        let mut c = ctx(&empty, &empty, &empty, &[]);
        c.protocol = None;
        c.response_code = None;
        c.duration = None;
        c.upstream_host = None;
        c.upstream_cluster = None;
        c.downstream_remote_address = None;
        let fs = parse(
            "%PROTOCOL% %RESPONSE_CODE% %DURATION% %UPSTREAM_HOST% %UPSTREAM_CLUSTER% %DOWNSTREAM_REMOTE_ADDRESS% %REQ(x)% %RESPONSE_FLAGS%",
        );
        assert_eq!(render(&fs, &c), "- - - - - - - -");
    }

    #[test]
    fn llm_list_cost_renders_nanodollars_or_dash_for_unpriced() {
        let empty = http::HeaderMap::new();
        let mut c = ctx(&empty, &empty, &empty, &[]);
        let format = parse("%LLM_LIST_COST%");
        assert_eq!(render(&format, &c), "-", "unpriced is not a free zero");
        c.llm_list_cost_nanodollars = Some(123_456);
        assert_eq!(render(&format, &c), "123456");
    }

    #[test]
    fn header_lookup_case_insensitive_and_fallback() {
        let mut req = http::HeaderMap::new();
        req.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
        let empty = http::HeaderMap::new();
        let c = ctx(&req, &empty, &empty, &[]);
        let fs = parse("%REQ(X-Forwarded-For)% %REQ(missing?X-Forwarded-For)%");
        assert_eq!(render(&fs, &c), "1.2.3.4 1.2.3.4");
    }

    #[test]
    fn truncation_applies_after_fallback_resolution() {
        let mut req = http::HeaderMap::new();
        req.insert("user-agent", "curl/8.0.0".parse().unwrap());
        let empty = http::HeaderMap::new();
        let c = ctx(&req, &empty, &empty, &[]);
        let fs = parse("%REQ(user-agent):4%");
        assert_eq!(render(&fs, &c), "curl");
    }

    #[test]
    fn response_flags_join_multi() {
        let empty = http::HeaderMap::new();
        let flags = [
            ResponseFlag::UpstreamConnectionFailure,
            ResponseFlag::UpstreamRetryLimitExceeded,
        ];
        let c = ctx(&empty, &empty, &empty, &flags);
        let fs = parse("%RESPONSE_FLAGS%");
        assert_eq!(render(&fs, &c), "UF,URX");
    }

    // -------------------------------------------- RESPONSE_CODE_DETAILS --

    #[test]
    fn response_code_details_renders_when_present() {
        let empty = http::HeaderMap::new();
        let mut c = ctx(&empty, &empty, &empty, &[]);
        c.response_code_details = Some("cluster_not_warmed");
        let fs = parse("%RESPONSE_CODE_DETAILS%");
        assert_eq!(render(&fs, &c), "cluster_not_warmed");
    }

    #[test]
    fn response_code_details_renders_dash_when_absent() {
        let empty = http::HeaderMap::new();
        let c = ctx(&empty, &empty, &empty, &[]);
        assert_eq!(c.response_code_details, None);
        let fs = parse("%RESPONSE_CODE_DETAILS%");
        assert_eq!(render(&fs, &c), "-");
    }

    #[test]
    fn start_time_default_and_custom_format() {
        let empty = http::HeaderMap::new();
        let c = ctx(&empty, &empty, &empty, &[]);
        let default = render(&parse("%START_TIME%"), &c);
        assert_eq!(default, "1970-01-01T00:00:00.000Z");
        let custom = render(&parse("%START_TIME(%s)%"), &c);
        assert_eq!(custom, "0");
    }

    /// The hand-written default `%START_TIME%` must match chrono's strftime
    /// byte for byte, including zero padding and millisecond truncation.
    #[test]
    fn default_start_time_fast_path_matches_chrono() {
        let empty = http::HeaderMap::new();
        let fmt = parse("%START_TIME%");
        let secs: [u64; 6] = [
            0,
            59,
            951_782_400,
            1_700_000_000,
            4_102_444_799,
            253_402_300_799,
        ];
        let nanos: [u32; 5] = [0, 999_999, 1_000_000, 123_456_789, 999_999_999];
        for s in secs {
            for n in nanos {
                let at = std::time::UNIX_EPOCH + std::time::Duration::new(s, n);
                let mut c = ctx(&empty, &empty, &empty, &[]);
                c.start_time = at;
                let dt: chrono::DateTime<chrono::Utc> = at.into();
                let chrono = dt.format(DEFAULT_START_TIME_FORMAT).to_string();
                assert_eq!(render(&fmt, &c), chrono, "{s}s {n}ns");
            }
        }
    }

    // -------------------------------------------------- request pseudo-headers --

    #[test]
    fn req_pseudo_headers_render_context_values() {
        let empty = http::HeaderMap::new();
        let c = ctx(&empty, &empty, &empty, &[]);
        let fs = parse("%REQ(:METHOD)% %REQ(:PATH)% %REQ(:AUTHORITY)% %REQ(:SCHEME)%");
        assert_eq!(
            render(&fs, &c),
            "POST /v1/chat/completions api.example.com https"
        );
    }

    #[test]
    fn req_pseudo_headers_case_insensitive() {
        let empty = http::HeaderMap::new();
        let c = ctx(&empty, &empty, &empty, &[]);
        let fs = parse("%REQ(:method)%");
        assert_eq!(render(&fs, &c), "POST");
    }

    #[test]
    fn req_pseudo_headers_render_dash_when_absent() {
        let empty = http::HeaderMap::new();
        let mut c = ctx(&empty, &empty, &empty, &[]);
        c.request_method = None;
        c.request_path = None;
        c.request_authority = None;
        c.request_scheme = None;
        let fs = parse("%REQ(:METHOD)% %REQ(:PATH)% %REQ(:AUTHORITY)% %REQ(:SCHEME)%");
        assert_eq!(render(&fs, &c), "- - - -");
    }

    #[test]
    fn req_unknown_pseudo_header_renders_dash_not_panic() {
        let empty = http::HeaderMap::new();
        let c = ctx(&empty, &empty, &empty, &[]);
        let fs = parse("%REQ(:BOGUS)%");
        assert_eq!(render(&fs, &c), "-");
    }

    #[test]
    fn resp_status_pseudo_header_renders_response_code() {
        let empty = http::HeaderMap::new();
        let c = ctx(&empty, &empty, &empty, &[]);
        let fs = parse("%RESP(:STATUS)%");
        assert_eq!(render(&fs, &c), "200");
    }

    #[test]
    fn resp_unknown_pseudo_header_renders_dash() {
        let empty = http::HeaderMap::new();
        let c = ctx(&empty, &empty, &empty, &[]);
        let fs = parse("%RESP(:BOGUS)%");
        assert_eq!(render(&fs, &c), "-");
    }

    #[test]
    fn req_original_path_fallback_prefers_header_then_falls_back_to_path_pseudo() {
        let empty = http::HeaderMap::new();
        let c = ctx(&empty, &empty, &empty, &[]);
        // No `x-envoy-original-path` header set -> falls back to `:PATH`.
        let fs = parse("%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%");
        assert_eq!(render(&fs, &c), "/v1/chat/completions");

        // Header present -> the primary wins over the `:PATH` fallback.
        let mut req = http::HeaderMap::new();
        req.insert("x-envoy-original-path", "/rewritten".parse().unwrap());
        let c2 = ctx(&req, &empty, &empty, &[]);
        let fs2 = parse("%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%");
        assert_eq!(render(&fs2, &c2), "/rewritten");
    }

    #[test]
    fn trailer_renders() {
        let empty = http::HeaderMap::new();
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().unwrap());
        let c = ctx(&empty, &empty, &trailers, &[]);
        let fs = parse("%TRAILER(grpc-status)%");
        assert_eq!(render(&fs, &c), "0");
    }

    const LLM_FMT: &str = "%LLM_INPUT_TOKENS% %LLM_CACHED_TOKENS% %LLM_CACHE_CREATION_TOKENS% %LLM_OUTPUT_TOKENS% %LLM_TOTAL_TOKENS% %LLM_TTFT%";

    #[test]
    fn llm_operators_render_populated_usage() {
        let empty = http::HeaderMap::new();
        let mut c = ctx(&empty, &empty, &empty, &[]);
        // Four distinct, non-zero values so a wrong-field bug in the total
        // (or in an individual operator) can't slip through by coincidence.
        c.llm_tokens = Some(LlmTokens {
            input: 11,
            cached: 22,
            cache_creation: 33,
            output: 44,
        });
        c.llm_ttft = Some(std::time::Duration::from_millis(250));
        let fs = parse(LLM_FMT);
        assert_eq!(render(&fs, &c), "11 22 33 44 110 250");
    }

    #[test]
    fn llm_operators_render_dash_when_absent() {
        // Absent usage/ttft must render `-`, never a confident `0` --
        // these numbers feed billing, and `0` would falsely claim the
        // provider reported zero tokens.
        let empty = http::HeaderMap::new();
        let c = ctx(&empty, &empty, &empty, &[]);
        assert_eq!(c.llm_tokens, None);
        assert_eq!(c.llm_ttft, None);
        let fs = parse(LLM_FMT);
        assert_eq!(render(&fs, &c), "- - - - - -");
    }

    #[test]
    fn llm_bogus_operator_is_rejected() {
        let e = parse_format("%LLM_BOGUS%").unwrap_err();
        assert!(e.0.contains("unknown access-log format operator"), "{e}");
        assert!(e.0.contains("LLM_BOGUS"), "{e}");
    }

    // -------------------------------------------------------- TPOT --

    const LLM_TPOT_FMT: &str = "%LLM_TPOT% %LLM_MAX_STALL% %LLM_RESPONSE_CHUNKS%";

    /// Every input is a distinct number, so a formula that reads the wrong field
    /// cannot pass by coincidence.
    #[test]
    fn llm_tpot_renders_mean_time_per_output_token() {
        let empty = http::HeaderMap::new();
        let mut c = ctx(&empty, &empty, &empty, &[]);
        c.duration = Some(std::time::Duration::from_millis(1000));
        c.llm_ttft = Some(std::time::Duration::from_millis(200));
        c.llm_tokens = Some(LlmTokens {
            input: 1,
            cached: 0,
            cache_creation: 0,
            output: 40,
        });
        // Distinct from the correct TPOT answer (20ms) so a mutant that
        // renders `max_inter_chunk` under `%LLM_TPOT%` is caught.
        c.llm_max_stall = Some(std::time::Duration::from_millis(150));
        c.llm_response_chunks = 7;
        let fs = parse(LLM_TPOT_FMT);
        // (1000 - 200) / 40 = 20ms exactly.
        assert_eq!(render(&fs, &c), "20.000 150 7");
    }

    /// Pins the sub-millisecond case. Dividing in milliseconds would render 0
    /// for fast providers, so nobody should "simplify" back to `as_millis()`.
    #[test]
    fn llm_tpot_keeps_sub_millisecond_precision_for_fast_streams() {
        let empty = http::HeaderMap::new();
        let mut c = ctx(&empty, &empty, &empty, &[]);
        // 2000 tokens generated in 1s after a 100ms TTFT = 0.5ms per token.
        c.duration = Some(std::time::Duration::from_millis(1100));
        c.llm_ttft = Some(std::time::Duration::from_millis(100));
        c.llm_tokens = Some(LlmTokens {
            input: 1,
            cached: 0,
            cache_creation: 0,
            output: 2000,
        });
        c.llm_max_stall = None;
        c.llm_response_chunks = 0;
        let fs = parse(LLM_TPOT_FMT);
        assert_eq!(
            render(&fs, &c),
            "0.500 - 0",
            "sub-millisecond TPOT must not collapse to 0"
        );
    }

    #[test]
    fn llm_tpot_renders_dash_when_output_tokens_zero() {
        let empty = http::HeaderMap::new();
        let mut c = ctx(&empty, &empty, &empty, &[]);
        c.duration = Some(std::time::Duration::from_millis(1000));
        c.llm_ttft = Some(std::time::Duration::from_millis(200));
        c.llm_tokens = Some(LlmTokens {
            input: 1,
            cached: 0,
            cache_creation: 0,
            output: 0,
        });
        let fs = parse("%LLM_TPOT%");
        assert_eq!(render(&fs, &c), "-");
    }

    #[test]
    fn llm_tpot_renders_dash_when_ttft_absent() {
        let empty = http::HeaderMap::new();
        let mut c = ctx(&empty, &empty, &empty, &[]);
        c.duration = Some(std::time::Duration::from_millis(1000));
        c.llm_ttft = None;
        c.llm_tokens = Some(LlmTokens {
            input: 1,
            cached: 0,
            cache_creation: 0,
            output: 40,
        });
        let fs = parse("%LLM_TPOT%");
        assert_eq!(render(&fs, &c), "-");
    }

    #[test]
    fn llm_tpot_renders_dash_when_duration_absent() {
        let empty = http::HeaderMap::new();
        let mut c = ctx(&empty, &empty, &empty, &[]);
        c.duration = None;
        c.llm_ttft = Some(std::time::Duration::from_millis(200));
        c.llm_tokens = Some(LlmTokens {
            input: 1,
            cached: 0,
            cache_creation: 0,
            output: 40,
        });
        let fs = parse("%LLM_TPOT%");
        assert_eq!(render(&fs, &c), "-");
    }

    #[test]
    fn llm_tpot_renders_dash_when_usage_absent() {
        let empty = http::HeaderMap::new();
        let mut c = ctx(&empty, &empty, &empty, &[]);
        c.duration = Some(std::time::Duration::from_millis(1000));
        c.llm_ttft = Some(std::time::Duration::from_millis(200));
        c.llm_tokens = None;
        let fs = parse("%LLM_TPOT%");
        assert_eq!(render(&fs, &c), "-");
    }

    #[test]
    fn llm_tpot_renders_dash_and_does_not_panic_when_duration_less_than_ttft() {
        // Clock/measurement skew: `Duration` subtraction PANICS on
        // underflow, so this must go through `checked_sub`, not `-`.
        let empty = http::HeaderMap::new();
        let mut c = ctx(&empty, &empty, &empty, &[]);
        c.duration = Some(std::time::Duration::from_millis(100));
        c.llm_ttft = Some(std::time::Duration::from_millis(200));
        c.llm_tokens = Some(LlmTokens {
            input: 1,
            cached: 0,
            cache_creation: 0,
            output: 40,
        });
        let fs = parse("%LLM_TPOT%");
        assert_eq!(render(&fs, &c), "-");
    }

    #[test]
    fn llm_max_stall_and_response_chunks_render_dash_and_zero_when_absent() {
        let empty = http::HeaderMap::new();
        let c = ctx(&empty, &empty, &empty, &[]);
        assert_eq!(c.llm_max_stall, None);
        assert_eq!(c.llm_response_chunks, 0);
        let fs = parse("%LLM_MAX_STALL% %LLM_RESPONSE_CHUNKS%");
        assert_eq!(render(&fs, &c), "- 0");
    }

    /// One format string combining every LLM operator, all rendered
    /// correctly together.
    #[test]
    fn all_llm_operators_render_together() {
        let empty = http::HeaderMap::new();
        let mut c = ctx(&empty, &empty, &empty, &[]);
        c.llm_tokens = Some(LlmTokens {
            input: 11,
            cached: 22,
            cache_creation: 33,
            output: 40,
        });
        c.llm_ttft = Some(std::time::Duration::from_millis(200));
        c.duration = Some(std::time::Duration::from_millis(1000));
        c.llm_max_stall = Some(std::time::Duration::from_millis(150));
        c.llm_response_chunks = 7;
        let fs = parse(&format!(
            "{LLM_FMT} %LLM_TPOT% %LLM_MAX_STALL% %LLM_RESPONSE_CHUNKS%"
        ));
        assert_eq!(render(&fs, &c), "11 22 33 40 106 200 20.000 150 7");
    }

    // ------------------------------------------------- %COMMON_DURATION% --

    #[test]
    fn common_duration_parses_every_point_and_precision() {
        for start in TimePoint::ALL {
            for end in TimePoint::ALL {
                let src = format!("%COMMON_DURATION({}:{})%", start.name(), end.name());
                assert_eq!(
                    parse(&src).0,
                    vec![FormatOp::CommonDuration {
                        start,
                        end,
                        precision: DurationPrecision::Milliseconds,
                    }],
                    "{src}"
                );
            }
        }
        for (suffix, precision) in [
            ("ms", DurationPrecision::Milliseconds),
            ("us", DurationPrecision::Microseconds),
            ("ns", DurationPrecision::Nanoseconds),
        ] {
            assert_eq!(
                parse(&format!("%COMMON_DURATION(DS_RX_BEG:DS_TX_END:{suffix})%")).0,
                vec![FormatOp::CommonDuration {
                    start: TimePoint::DsRxBeg,
                    end: TimePoint::DsTxEnd,
                    precision,
                }]
            );
        }
    }

    #[test]
    fn common_duration_rejects_malformed_arguments() {
        for (src, needle) in [
            ("%COMMON_DURATION%", "requires"),
            ("%COMMON_DURATION(DS_RX_BEG)%", "expected `START:END`"),
            (
                "%COMMON_DURATION(DS_RX_BEG:DS_RX_END:ms:x)%",
                "expected `START:END`",
            ),
            ("%COMMON_DURATION(DS_RX_BEG:DS_RX_END:s)%", "precision `s`"),
            // Case-sensitive, as in Envoy.
            (
                "%COMMON_DURATION(DS_RX_BEG:DS_RX_END:MS)%",
                "precision `MS`",
            ),
            ("%COMMON_DURATION(ds_rx_beg:DS_RX_END)%", "`ds_rx_beg`"),
            // Envoy would read this as a custom time point; nothing here sets
            // one, so it is a config error rather than a column of `-`.
            (
                "%COMMON_DURATION(DS_RX_BEG:MY_FILTER_POINT)%",
                "`MY_FILTER_POINT`",
            ),
            ("%COMMON_DURATION(DS_RX_BEG:DS_RX_END):5%", "truncation"),
        ] {
            let e = parse_format(src).unwrap_err();
            assert!(e.0.contains(needle), "{src}: {e}");
        }
    }

    /// Each point renders on its own: set only that point and the span from
    /// it to itself is `0`, while a span to any unset point is `-`.
    #[test]
    fn common_duration_renders_each_point_and_dash_for_a_missing_one() {
        let empty = http::HeaderMap::new();
        let at = std::time::Instant::now();
        for point in TimePoint::ALL {
            let mut c = ctx(&empty, &empty, &empty, &[]);
            c.time_points.set(point, Some(at));
            let same = parse(&format!("%COMMON_DURATION({0}:{0})%", point.name()));
            assert_eq!(render(&same, &c), "0", "{}", point.name());
            for other in TimePoint::ALL.into_iter().filter(|p| *p != point) {
                let to = parse(&format!(
                    "%COMMON_DURATION({}:{})% %COMMON_DURATION({}:{})%",
                    point.name(),
                    other.name(),
                    other.name(),
                    point.name()
                ));
                assert_eq!(
                    render(&to, &c),
                    "- -",
                    "{} / {}",
                    point.name(),
                    other.name()
                );
            }
        }
    }

    #[test]
    fn common_duration_truncates_to_the_precision_and_dashes_a_negative_span() {
        let empty = http::HeaderMap::new();
        let mut c = ctx(&empty, &empty, &empty, &[]);
        let start = std::time::Instant::now();
        let end = start + std::time::Duration::from_nanos(1_234_567);
        c.time_points.set(TimePoint::UsTxEnd, Some(start));
        c.time_points.set(TimePoint::UsRxBeg, Some(end));
        let fs = parse(
            "%COMMON_DURATION(US_TX_END:US_RX_BEG)% %COMMON_DURATION(US_TX_END:US_RX_BEG:ms)% \
             %COMMON_DURATION(US_TX_END:US_RX_BEG:us)% %COMMON_DURATION(US_TX_END:US_RX_BEG:ns)% \
             %COMMON_DURATION(US_RX_BEG:US_TX_END:ns)%",
        );
        // Envoy returns no value when END precedes START, rendered `-`.
        assert_eq!(render(&fs, &c), "1 1 1234 1234567 -");
    }
}
