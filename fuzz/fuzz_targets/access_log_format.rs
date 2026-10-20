//! Access-log format strings (`proxy-observability` `access_log.rs`): the
//! load-time parser and the per-request renderer. The operator writes the
//! format, but it arrives through xDS and reload too, and the renderer runs
//! on every request with client-controlled header values.
//!
//! Input: the format string.
//!
//! Properties checked beyond "never panic":
//! - round trip: printing a parsed format back to text and parsing it again
//!   gives the same operators;
//! - rendering is compositional: the whole line is the concatenation of each
//!   operator rendered alone;
//! - a `%REQ%`/`%RESP%`/`%TRAILER%` with `:Z` renders at most `Z` characters;
//! - a credential header's value never reaches the line, whatever the format
//!   names (the `%REQ%` redaction, `internal-docs/envoy-divergences.md`);
//! - a `%START_TIME(...)%` pattern the parser accepts renders in full: chrono
//!   stops writing at the first specifier it cannot format, and a field that
//!   loads but renders a truncated line is a silently ignored setting.
#![no_main]

use std::fmt::Write as _;
use std::time::{Duration, SystemTime};

use libfuzzer_sys::fuzz_target;
use proxy_observability::access_log::{
    parse_format, render, DurationPrecision, FormatOp, FormatString, HeaderSpec, LlmMedia,
    LlmTokens, LogContext, TimePoint, TimePoints,
};

/// A value no format can name: the target skips inputs that contain it.
const SECRET: &str = "sk-fuzz-secret-7f3a";

const CREDENTIAL_HEADERS: [&str; 6] = [
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
    "cookie",
];

fn escape(text: &str) -> String {
    text.replace('%', "%%")
}

fn print_header(name: &str, spec: &HeaderSpec, out: &mut String) {
    let _ = write!(out, "%{name}({}", spec.primary);
    if let Some(fallback) = &spec.fallback {
        let _ = write!(out, "?{fallback}");
    }
    out.push(')');
    if let Some(n) = spec.truncate {
        let _ = write!(out, ":{n}");
    }
    out.push('%');
}

/// The canonical text of a parsed format.
fn print(format: &FormatString) -> String {
    let mut out = String::new();
    for op in &format.0 {
        let bare = match op {
            FormatOp::Literal(text) => {
                out.push_str(&escape(text));
                continue;
            }
            FormatOp::StartTime(None) => "START_TIME",
            FormatOp::StartTime(Some(pattern)) => {
                let _ = write!(out, "%START_TIME({pattern})%");
                continue;
            }
            FormatOp::Req(spec) => {
                print_header("REQ", spec, &mut out);
                continue;
            }
            FormatOp::Resp(spec) => {
                print_header("RESP", spec, &mut out);
                continue;
            }
            FormatOp::Trailer(spec) => {
                print_header("TRAILER", spec, &mut out);
                continue;
            }
            FormatOp::CommonDuration {
                start,
                end,
                precision,
            } => {
                let precision = match precision {
                    DurationPrecision::Milliseconds => "ms",
                    DurationPrecision::Microseconds => "us",
                    DurationPrecision::Nanoseconds => "ns",
                };
                let _ = write!(
                    out,
                    "%COMMON_DURATION({}:{}:{precision})%",
                    start.name(),
                    end.name()
                );
                continue;
            }
            FormatOp::Protocol => "PROTOCOL",
            FormatOp::ResponseCode => "RESPONSE_CODE",
            FormatOp::ResponseFlags => "RESPONSE_FLAGS",
            FormatOp::ResponseCodeDetails => "RESPONSE_CODE_DETAILS",
            FormatOp::Duration => "DURATION",
            FormatOp::BytesReceived => "BYTES_RECEIVED",
            FormatOp::BytesSent => "BYTES_SENT",
            FormatOp::UpstreamHost => "UPSTREAM_HOST",
            FormatOp::UpstreamCluster => "UPSTREAM_CLUSTER",
            FormatOp::DownstreamRemoteAddress => "DOWNSTREAM_REMOTE_ADDRESS",
            FormatOp::LlmInputTokens => "LLM_INPUT_TOKENS",
            FormatOp::LlmCachedTokens => "LLM_CACHED_TOKENS",
            FormatOp::LlmCacheCreationTokens => "LLM_CACHE_CREATION_TOKENS",
            FormatOp::LlmOutputTokens => "LLM_OUTPUT_TOKENS",
            FormatOp::LlmTotalTokens => "LLM_TOTAL_TOKENS",
            FormatOp::LlmTtft => "LLM_TTFT",
            FormatOp::LlmTpot => "LLM_TPOT",
            FormatOp::LlmMaxStall => "LLM_MAX_STALL",
            FormatOp::LlmResponseChunks => "LLM_RESPONSE_CHUNKS",
            FormatOp::LlmListCost => "LLM_LIST_COST",
            FormatOp::LlmKeyId => "LLM_KEY_ID",
            FormatOp::LlmTenant => "LLM_TENANT",
            FormatOp::LlmCredentialSource => "LLM_CREDENTIAL_SOURCE",
            FormatOp::LlmUserId => "LLM_USER_ID",
            FormatOp::LlmRequestedModel => "LLM_REQUESTED_MODEL",
            FormatOp::LlmResolvedModel => "LLM_RESOLVED_MODEL",
            FormatOp::LlmSelectedModel => "LLM_SELECTED_MODEL",
            FormatOp::LlmServedModel => "LLM_SERVED_MODEL",
            FormatOp::LlmUpstreamId => "LLM_UPSTREAM_ID",
            FormatOp::LlmUpstreamUsage => "LLM_UPSTREAM_USAGE",
            FormatOp::LlmUsageCompleteness => "LLM_USAGE_COMPLETENESS",
            FormatOp::LlmCostKind => "LLM_COST_KIND",
            FormatOp::LlmRateCardVersion => "LLM_RATE_CARD_VERSION",
            FormatOp::LlmImages => "LLM_IMAGES",
            FormatOp::LlmInputCharacters => "LLM_INPUT_CHARACTERS",
            FormatOp::LlmAudioMs => "LLM_AUDIO_MS",
            FormatOp::LlmInputImageTokens => "LLM_INPUT_IMAGE_TOKENS",
            FormatOp::LlmOutputImageTokens => "LLM_OUTPUT_IMAGE_TOKENS",
            FormatOp::LlmInputAudioTokens => "LLM_INPUT_AUDIO_TOKENS",
            FormatOp::LlmOutputAudioTokens => "LLM_OUTPUT_AUDIO_TOKENS",
            FormatOp::LlmPriceBasis => "LLM_PRICE_BASIS",
        };
        let _ = write!(out, "%{bare}%");
    }
    out
}

fn context<'a>(
    request: &'a http::HeaderMap,
    response: &'a http::HeaderMap,
    trailers: &'a http::HeaderMap,
) -> LogContext<'a> {
    let base = std::time::Instant::now();
    let mut time_points = TimePoints::default();
    for (i, point) in TimePoint::ALL.into_iter().enumerate() {
        time_points.set(point, Some(base + Duration::from_micros(1_500 * i as u64)));
    }
    LogContext {
        start_time: SystemTime::UNIX_EPOCH + Duration::from_millis(1_760_000_000_123),
        request_headers: request,
        response_headers: response,
        response_trailers: trailers,
        protocol: Some("HTTP/1.1"),
        response_code: Some(200),
        response_flags: &[],
        duration: Some(Duration::from_millis(1_234)),
        bytes_received: 10,
        bytes_sent: 20,
        upstream_host: Some("10.0.0.1:8080"),
        upstream_cluster: Some("provider:a"),
        downstream_remote_address: Some("127.0.0.1:1234"),
        response_code_details: Some("via_upstream"),
        llm_tokens: Some(LlmTokens {
            input: 7,
            cached: 3,
            cache_creation: 2,
            output: 11,
        }),
        llm_ttft: Some(Duration::from_millis(120)),
        llm_max_stall: Some(Duration::from_millis(40)),
        llm_response_chunks: 5,
        llm_list_cost_nanodollars: Some(1_000),
        llm_key_id: Some("key-1"),
        llm_tenant: Some("tenant-a"),
        llm_credential_source: Some("platform"),
        llm_user_id: Some("user-1"),
        llm_requested_model: Some("gpt-4o"),
        llm_resolved_model: None,
        llm_selected_model: Some("gpt-4o"),
        llm_served_model: Some("gpt-4o-2024-08-06"),
        llm_upstream_id: Some("chatcmpl-1"),
        llm_upstream_usage: Some(r#"{"prompt_tokens":7}"#),
        llm_usage_completeness: Some("complete"),
        llm_cost_kind: Some("list"),
        llm_rate_card_version: Some("v1"),
        llm_media: LlmMedia {
            images: Some(2),
            input_characters: Some(30),
            audio_milliseconds: Some(1500),
            input_image_tokens: Some(4),
            output_image_tokens: Some(5),
            input_audio_tokens: Some(6),
            output_audio_tokens: Some(7),
            price_basis: Some("images"),
        },
        time_points,
        request_method: Some("POST"),
        request_path: Some("/v1/chat/completions"),
        request_authority: Some("api.example.com"),
        request_scheme: Some("https"),
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(format) = parse_format(input) else {
        return;
    };

    let printed = print(&format);
    let reparsed = parse_format(&printed).unwrap_or_else(|err| {
        panic!("printed form {printed:?} of {input:?} does not parse: {err}")
    });
    assert_eq!(reparsed, format, "round trip through {printed:?}");

    let mut request = http::HeaderMap::new();
    for name in CREDENTIAL_HEADERS {
        request.insert(name, http::HeaderValue::from_static(SECRET));
    }
    request.insert("user-agent", http::HeaderValue::from_static("curl/8.0.0"));
    request.insert(
        "x-long",
        http::HeaderValue::from_str(&"abcdefghij".repeat(50)).unwrap(),
    );
    let mut response = http::HeaderMap::new();
    response.insert(
        "content-type",
        http::HeaderValue::from_static("application/json"),
    );
    response.insert(
        "x-long",
        http::HeaderValue::from_str(&"0123456789".repeat(50)).unwrap(),
    );
    let trailers = response.clone();
    let ctx = context(&request, &response, &trailers);

    let line = render(&format, &ctx);
    let mut pieces = String::new();
    for op in &format.0 {
        let piece = render(&FormatString(vec![op.clone()]), &ctx);
        match op {
            FormatOp::Req(spec) | FormatOp::Resp(spec) | FormatOp::Trailer(spec) => {
                if let Some(n) = spec.truncate {
                    assert!(
                        piece.chars().count() <= n.max(1),
                        "{op:?} rendered {} chars",
                        piece.chars().count()
                    );
                }
            }
            FormatOp::StartTime(Some(pattern)) => {
                let full = chrono::format::StrftimeItems::new(pattern)
                    .all(|item| !matches!(item, chrono::format::Item::Error));
                assert!(
                    full,
                    "accepted START_TIME pattern {pattern:?} cannot be rendered"
                );
            }
            _ => {}
        }
        pieces.push_str(&piece);
    }
    assert_eq!(line, pieces, "rendering is not compositional");
    if !input.contains(SECRET) {
        assert!(
            !line.contains(SECRET),
            "credential reached the log line: {line:?}"
        );
    }
});
