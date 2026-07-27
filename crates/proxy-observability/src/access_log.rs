//! WP-24 (chunk 1): the access-log format-string engine.
//!
//! Two halves, deliberately separated by cost:
//!
//! - [`parse_format`] runs once, at config-load time, turning an Envoy
//!   format string (e.g. `"[%START_TIME%] %REQ(:METHOD)%\n"`) into a
//!   [`FormatString`] — an ordered `Vec` of literal text and pre-resolved
//!   [`FormatOp`]s. An unknown `%OPERATOR%` is rejected here, not silently
//!   dropped or emitted as literal text (ground rule #1).
//! - [`render`] runs per request, on the hot path: it never re-parses
//!   anything, just walks the pre-built op list and writes into a `String`.
//!
//! Runtime sink wiring (actually calling `render` from the router/filter
//! manager and writing the result somewhere) is WP-24 chunk 2, not here.

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
/// Rust note: this is a classic "parse, don't validate" enum — every variant
/// that reached here is already known-good (right arity, right operator
/// name), so [`render`] can never fail; it only has to handle *absent data*
/// (render `-`), not *malformed format strings* (rejected in
/// [`parse_format`]).
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
    Duration,
    BytesReceived,
    BytesSent,
    UpstreamHost,
    UpstreamCluster,
    DownstreamRemoteAddress,
    /// WP-33: `%LLM_INPUT_TOKENS%`.
    LlmInputTokens,
    /// WP-33: `%LLM_CACHED_TOKENS%`.
    LlmCachedTokens,
    /// WP-33: `%LLM_CACHE_CREATION_TOKENS%`.
    LlmCacheCreationTokens,
    /// WP-33: `%LLM_OUTPUT_TOKENS%`.
    LlmOutputTokens,
    /// WP-33: `%LLM_TOTAL_TOKENS%` -- the sum of all four buckets above.
    LlmTotalTokens,
    /// WP-33: `%LLM_TTFT%` -- time-to-first-token, in milliseconds.
    LlmTtft,
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
/// path (this crate doesn't know about that type — ground rule #2 keeps
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
    /// is a config error, not silently ignored (ground rule #1).
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
        "DURATION" => {
            bare(name, args, truncate, input)?;
            FormatOp::Duration
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
        other => {
            return Err(err(format!(
                "unknown access-log format operator `%{other}%` in format string `{input}`"
            )))
        }
    })
}

// ------------------------------------------------------------- rendering --

/// Envoy's default `%START_TIME%` rendering: ISO-8601 with millisecond
/// precision and a literal `Z` (matches Envoy's `DEFAULT_TIME_FORMAT`,
/// `%Y-%m-%dT%H:%M:%E3SZ`, which chrono's strftime dialect spells with
/// `%.3f` instead of the abseil-specific `%E3S`).
const DEFAULT_START_TIME_FORMAT: &str = "%Y-%m-%dT%H:%M:%S%.3fZ";

/// WP-33: provider-reported token usage, in the four billing buckets --
/// mirrors `proxy_http::LlmTokenUsage` field-for-field, but this crate can't
/// name that type (`proxy-observability` is a *dependency* of `proxy-http`,
/// not the other way around -- ground rule #2's direction applies to crate
/// layering here too), so the caller (`proxy-http::router::logging`) converts
/// at the boundary.
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

/// Everything a request/stream lifecycle knows by the time it's logged.
/// Built by the caller (chunk 2: the router / filter manager) and handed to
/// [`render`]; this type has no knowledge of how those fields were computed.
///
/// Rust note: `'a` ties every borrowed field to the caller's stack frame —
/// `LogContext` never owns data, it's a read-only view assembled just before
/// rendering, so building one doesn't allocate.
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
    /// WP-33: provider-reported token usage. `None` when the response
    /// carried none -- a non-LLM route, or a provider that reported nothing.
    pub llm_tokens: Option<LlmTokens>,
    /// WP-33: time-to-first-token -- response headers to first body byte.
    pub llm_ttft: Option<std::time::Duration>,
}

/// Render a parsed format string against a request's context. Allocation is
/// limited to the single output `String` (grown in place) plus one
/// `String` per truncated header value; no per-operator heap churn beyond
/// that render path.
pub fn render(fmt: &FormatString, ctx: &LogContext<'_>) -> String {
    let mut out = String::new();
    for op in &fmt.0 {
        render_op(op, ctx, &mut out);
    }
    out
}

fn render_op(op: &FormatOp, ctx: &LogContext<'_>, out: &mut String) {
    match op {
        FormatOp::Literal(s) => out.push_str(s),
        FormatOp::StartTime(fmt) => {
            let dt: chrono::DateTime<chrono::Utc> = ctx.start_time.into();
            let pattern = fmt.as_deref().unwrap_or(DEFAULT_START_TIME_FORMAT);
            let _ = write!(out, "{}", dt.format(pattern));
        }
        FormatOp::Req(spec) => render_header(ctx.request_headers, spec, out),
        FormatOp::Resp(spec) => render_header(ctx.response_headers, spec, out),
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
        // WP-33: these six feed billing, so absent usage must render `-`,
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
    }
}

fn render_header(map: &http::HeaderMap, spec: &HeaderSpec, out: &mut String) {
    let mut value = header_lookup(map, &spec.primary);
    if value.is_none() {
        if let Some(fallback) = &spec.fallback {
            value = header_lookup(map, fallback);
        }
    }
    match value {
        Some(v) => match spec.truncate {
            Some(n) if v.chars().count() > n => out.extend(v.chars().take(n)),
            _ => out.push_str(v),
        },
        None => out.push('-'),
    }
}

/// Header lookup by name, including Envoy pseudo-header names like
/// `:method`/`:authority` that aren't valid `http::HeaderName` tokens (the
/// colon isn't allowed in an HTTP field-name) — those simply never match
/// today (rendered as `-`) until a caller starts populating a pseudo-header
/// under a real key. This never panics on a malformed operator argument.
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
            llm_tokens: None,
            llm_ttft: None,
        }
    }

    #[test]
    fn renders_scalars() {
        let empty = http::HeaderMap::new();
        let c = ctx(&empty, &empty, &empty, &[]);
        let fs = parse("%PROTOCOL% %RESPONSE_CODE% %DURATION% %BYTES_RECEIVED% %BYTES_SENT% %UPSTREAM_HOST% %UPSTREAM_CLUSTER% %DOWNSTREAM_REMOTE_ADDRESS%");
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
        let fs = parse("%PROTOCOL% %RESPONSE_CODE% %DURATION% %UPSTREAM_HOST% %UPSTREAM_CLUSTER% %DOWNSTREAM_REMOTE_ADDRESS% %REQ(x)% %RESPONSE_FLAGS%");
        assert_eq!(render(&fs, &c), "- - - - - - - -");
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

    #[test]
    fn start_time_default_and_custom_format() {
        let empty = http::HeaderMap::new();
        let c = ctx(&empty, &empty, &empty, &[]);
        let default = render(&parse("%START_TIME%"), &c);
        assert_eq!(default, "1970-01-01T00:00:00.000Z");
        let custom = render(&parse("%START_TIME(%s)%"), &c);
        assert_eq!(custom, "0");
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
        // WP-33: absent usage/ttft must render `-`, never a confident `0` --
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
}
