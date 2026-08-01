//! WP-33a — wires the WP-34 [`crate::usage`] extractor into the real HTTP
//! encode path.
//!
//! This is the filter that actually watches response bytes go by: it picks a
//! parsing strategy off `content-type`, feeds bytes to the right extractor as
//! they arrive, and writes the result (plus TTFT/inter-chunk timing) into
//! [`StreamInfo::llm`] once the response ends.
//!
//! # The one rule that matters more than any other
//!
//! This filter must **never** buffer the response. WP-33's whole product bet
//! is that a client streaming tokens from an LLM sees them as they're
//! generated, not after the proxy has assembled the full response. See the
//! `// Rust note:` on [`UsageFilterInstance::encode_data`] for the mechanical
//! guarantee.
//!
//! # Config: reusing `DataSource` (INTERIM)
//!
//! Same rationale as `proxy-core`'s `header_mutation_filter` (see that
//! module's doc comment): rather than vendoring a brand-new Lane-H proto for
//! a filter that today has exactly one config field, `typed_config` reuses
//! the already-compiled `envoy.config.core.v3.DataSource` message and reads
//! its `inline_string` field as the dialect name (`"openai"` /
//! `"anthropic"`, case-insensitive). An Any's type URL is just an opaque
//! `prefix/full.type.name` string — only the suffix needs to resolve against
//! the descriptor pool — so pointing `type.llmproxy.dev` at `DataSource` is
//! legal, if a little unusual. Once this filter grows a second config field
//! (per-dialect overrides, a token-rate-limit budget knob, etc.) it should
//! get its own vendored proto instead of stretching `DataSource` further.

use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use http::HeaderMap;
use prost_reflect::DynamicMessage;

use proxy_config::ConfigError;
use std::sync::Arc;

use proxy_http::filter::{
    EncoderCallbacks, FactoryContext, FilterDataStatus, FilterHeadersStatus, FilterInstanceFactory,
    FilterTrailersStatus, HttpFilter, HttpFilterFactory, PerRouteConfig, ResponseHeaders,
    ResponseTrailers,
};
use proxy_http::LlmTokenUsage;

use crate::usage::{extract_json_usage, Dialect, SseUsageScanner, TokenUsage};

/// Type URL this filter is registered under (see the module doc for the
/// `DataSource`-reuse rationale).
pub const TYPE_URL: &str = "type.llmproxy.dev/envoy.config.core.v3.DataSource";

/// Upper bound on the response body this filter will accumulate to parse as a
/// single non-streaming JSON document. A response over this size still
/// streams through to the client untouched (see [`UsageFilterInstance::encode_data`]) —
/// this cap only decides whether *we* keep trying to compute usage for it.
pub const MAX_JSON_BODY_BYTES: usize = 1 << 20; // 1 MiB

/// Convert a [`TokenUsage`] into the [`LlmTokenUsage`] that `StreamInfo`
/// carries. All four cost buckets cross the boundary intact — dropping the
/// cache buckets would leave anything downstream (billing, the WP-34 token
/// limiter) unable to compute a correct cost, since the buckets are priced
/// differently.
///
/// Rust note: `From` is the idiomatic "one type converts unambiguously into
/// another" trait; implementing it here (rather than a free function) lets
/// callers write `usage.into()` and is what `stream_info.rs`'s doc comment on
/// `LlmTokenUsage` means by "the usage filter converts at its boundary".
impl From<TokenUsage> for LlmTokenUsage {
    fn from(usage: TokenUsage) -> Self {
        LlmTokenUsage {
            input_tokens: usage.input_tokens,
            cached_tokens: usage.cached_tokens,
            cache_creation_tokens: usage.cache_creation_tokens,
            output_tokens: usage.output_tokens,
        }
    }
}

/// [`HttpFilterFactory`] for [`TYPE_URL`].
#[derive(Default)]
pub struct UsageFilterFactory;

impl HttpFilterFactory for UsageFilterFactory {
    fn type_url(&self) -> &'static str {
        TYPE_URL
    }

    fn create(
        &self,
        config: &DynamicMessage,
        _ctx: &FactoryContext,
    ) -> Result<Box<dyn FilterInstanceFactory>, ConfigError> {
        let dialect = parse_config(config)?;
        Ok(Box::new(UsageFilterInstanceFactory { dialect }))
    }

    fn parse_per_route(
        &self,
        config: &DynamicMessage,
    ) -> Result<Arc<dyn PerRouteConfig>, ConfigError> {
        let dialect = parse_config(config)?;
        Ok(Arc::new(UsagePerRouteConfig(dialect)))
    }
}

/// Read the configured dialect out of a `DataSource`-shaped `typed_config`.
fn parse_config(config: &DynamicMessage) -> Result<Dialect, ConfigError> {
    let invalid = |reason: String| ConfigError::InvalidValue {
        field_path: "typed_config.inline_string".to_string(),
        reason,
    };

    let raw = config
        .get_field_by_name("inline_string")
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();

    match raw.to_ascii_lowercase().as_str() {
        "openai" => Ok(Dialect::OpenAi),
        "anthropic" => Ok(Dialect::Anthropic),
        _ => Err(invalid(format!(
            "expected `openai` or `anthropic`, got `{raw}`"
        ))),
    }
}

/// Created once per (filter config, listener); stateless beyond the parsed
/// dialect, so building a fresh per-stream instance is cheap.
struct UsagePerRouteConfig(Dialect);

impl PerRouteConfig for UsagePerRouteConfig {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

struct UsageFilterInstanceFactory {
    dialect: Dialect,
}

impl FilterInstanceFactory for UsageFilterInstanceFactory {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(UsageFilterInstance {
            dialect: self.dialect,
            mode: BodyMode::Inert,
            headers_at: None,
            last_chunk_at: None,
            time_to_first_byte: None,
            max_inter_chunk: None,
            response_chunks: 0,
            finalized: false,
        })
    }
}

/// Rust note: an enum used as a small state machine — which strategy (if any)
/// this stream's body is being read with. Matching on it is exhaustive, so
/// adding a fourth mode later forces every call site here to decide what it
/// does in that case (ground rule #1's spirit, applied to our own code).
enum BodyMode {
    /// `text/event-stream`: feed chunks to the incremental SSE scanner.
    Sse(SseUsageScanner),
    /// `application/json`: accumulate the body, up to [`MAX_JSON_BODY_BYTES`].
    Json(BytesMut),
    /// Anything else (including "haven't seen headers yet"): do nothing.
    Inert,
}

/// Per-stream instance. One of these is created per response, per the frozen
/// `HttpFilter` contract (see `filter.rs`'s module doc) — so `!Send` interior
/// state (plain fields here, no `Rc`/`RefCell` needed) is safe: it never
/// leaves the worker thread that owns this stream.
struct UsageFilterInstance {
    dialect: Dialect,
    mode: BodyMode,
    /// When response headers were flushed — the TTFT baseline. `Instant`
    /// (not `SystemTime`) because we only ever compare it to another `Instant`
    /// on the same clock to get a duration; we never need it as a wall-clock
    /// timestamp.
    headers_at: Option<Instant>,
    /// When the previous response body chunk arrived. `None` means "no chunk
    /// yet" — the same `Option<Instant>` pattern as `headers_at`, distinct
    /// from `Some(Instant)` meaning "seen one, here's when".
    last_chunk_at: Option<Instant>,
    time_to_first_byte: Option<Duration>,
    max_inter_chunk: Option<Duration>,
    response_chunks: u64,
    /// Guards against writing `StreamInfo` twice — `encode_data` with
    /// `end_stream=true` and a later `encode_trailers` (or vice versa) must
    /// not both finalize.
    finalized: bool,
}

/// Pick a [`BodyMode`] from the response's `content-type`, matching only the
/// media type (before any `;` parameters), ASCII-case-insensitively. Absent
/// or unrecognized content types get [`BodyMode::Inert`] — we do not guess.
fn classify_body(headers: &HeaderMap, dialect: Dialect) -> BodyMode {
    let Some(value) = headers.get(http::header::CONTENT_TYPE) else {
        return BodyMode::Inert;
    };
    let Ok(value) = value.to_str() else {
        return BodyMode::Inert;
    };
    let media_type = value.split(';').next().unwrap_or("").trim();

    if media_type.eq_ignore_ascii_case("text/event-stream") {
        BodyMode::Sse(SseUsageScanner::new(dialect))
    } else if media_type.eq_ignore_ascii_case("application/json") {
        BodyMode::Json(BytesMut::new())
    } else {
        BodyMode::Inert
    }
}

impl UsageFilterInstance {
    /// Update chunk-timing bookkeeping for one arriving body chunk. Called
    /// once per `encode_data`, before the chunk is handed to the body-mode
    /// scanner, so timing is tracked even in [`BodyMode::Inert`].
    fn record_chunk_timing(&mut self) {
        let now = Instant::now();
        // The gap is measured from the previous chunk, or — for the very
        // first chunk — from when headers flushed (the TTFT definition).
        let previous = self.last_chunk_at.or(self.headers_at).unwrap_or(now); // encode_headers always runs first in practice;
                                                                              // this fallback just avoids a negative/undefined gap if it somehow didn't.
        let gap = now.duration_since(previous);

        if self.response_chunks == 0 {
            self.time_to_first_byte = Some(gap);
        } else {
            self.max_inter_chunk = Some(match self.max_inter_chunk {
                Some(running_max) => running_max.max(gap),
                None => gap,
            });
        }

        self.response_chunks += 1;
        self.last_chunk_at = Some(now);
    }

    /// Compute the final usage (if any) for the current body mode, without
    /// consuming `self.mode` — cheap enough (an `Option<TokenUsage>` and a
    /// JSON parse of an already-bounded buffer) that borrowing is simplest.
    fn compute_usage(&self) -> Option<TokenUsage> {
        match &self.mode {
            BodyMode::Sse(scanner) => scanner.usage(),
            BodyMode::Json(buf) => extract_json_usage(self.dialect, buf),
            BodyMode::Inert => None,
        }
    }

    /// Write the observed usage + timing into `StreamInfo::llm`, exactly
    /// once. Safe to call from more than one callback (`encode_data` at
    /// `end_stream`, `encode_trailers`) — the second call is a no-op.
    fn finalize(&mut self, cb: &mut dyn EncoderCallbacks) {
        if self.finalized {
            return;
        }
        self.finalized = true;

        let usage = self.compute_usage();
        // Rust note: `stream_info()` hands back a `RefMut` guard, not a plain
        // `&mut` — the stream's single `StreamInfo` is shared (`Rc<RefCell<_>>`)
        // between the filter chain and the router. `RefMut` derefs to
        // `&mut StreamInfo`, so the field writes below are unchanged; the guard
        // just must not be held across another `cb` call, or the `RefCell`
        // panics. It's dropped at the end of this function.
        let mut stream_info = cb.stream_info();
        // `None` must stay `None` here — never write `Some(0, 0)` for a
        // response that reported no usage at all (WP-34's rule; this number
        // feeds billing, and a wrong zero is worse than an honest "unknown").
        stream_info.llm.usage = usage.map(LlmTokenUsage::from);
        stream_info.llm.time_to_first_byte = self.time_to_first_byte;
        stream_info.llm.max_inter_chunk = self.max_inter_chunk;
        stream_info.llm.response_chunks = self.response_chunks;
    }
}

impl HttpFilter for UsageFilterInstance {
    fn encode_headers(
        &mut self,
        cb: &mut dyn EncoderCallbacks,
        headers: &mut ResponseHeaders,
        end_stream: bool,
    ) -> FilterHeadersStatus {
        self.headers_at = Some(Instant::now());
        let dialect = cb
            .per_route_config()
            .and_then(|cfg| {
                cfg.as_any()
                    .downcast_ref::<UsagePerRouteConfig>()
                    .map(|c| c.0)
            })
            .unwrap_or(self.dialect);
        self.dialect = dialect;
        self.mode = classify_body(&headers.headers, dialect);

        // A response with no body at all (e.g. a 204, or a HEAD reply) — there's
        // nothing more to observe, so finalize right here.
        if end_stream {
            self.finalize(cb);
        }
        FilterHeadersStatus::Continue
    }

    fn encode_data(
        &mut self,
        cb: &mut dyn EncoderCallbacks,
        data: &mut Bytes,
        end_stream: bool,
    ) -> FilterDataStatus {
        self.record_chunk_timing();

        match &mut self.mode {
            BodyMode::Sse(scanner) => scanner.push(data),
            BodyMode::Json(buf) => {
                if buf.len() + data.len() > MAX_JSON_BODY_BYTES {
                    // Drop into inert mode rather than keep a truncated
                    // prefix: a partial JSON parse could silently produce a
                    // wrong (not just missing) token count, and this number
                    // feeds billing.
                    self.mode = BodyMode::Inert;
                } else {
                    buf.extend_from_slice(data);
                }
            }
            BodyMode::Inert => {}
        }

        if end_stream {
            self.finalize(cb);
        }

        // Rust note: this is the single most important line in the filter.
        // `Continue` (never any `StopIteration*` variant, and we never call
        // `cb.add_encoded_data`) means the filter manager passes every chunk
        // straight through to the next filter/downstream as it arrives. A
        // buffering encode filter here — even one that "just peeks and then
        // continues" via `StopIterationAndBuffer` — would hold the whole
        // response until the buffer's flushed, which destroys the one thing
        // that makes an LLM proxy usable: token-by-token streaming to the
        // client as the model generates them.
        FilterDataStatus::Continue
    }

    fn encode_trailers(
        &mut self,
        cb: &mut dyn EncoderCallbacks,
        _trailers: &mut ResponseTrailers,
    ) -> FilterTrailersStatus {
        // A response can end with trailers instead of an end_stream data
        // frame (chunked-with-trailers, gRPC-style status trailers, etc.);
        // finalize here if `encode_data` never saw `end_stream=true`.
        self.finalize(cb);
        FilterTrailersStatus::Continue
    }

    // `on_destroy` deliberately has no override here. Its contract (see
    // `filter.rs`) is `fn on_destroy(&mut self)` — no callbacks parameter —
    // so a reset-mid-stream path has no `StreamInfo` to write into even
    // though `self` still holds the timing/chunk counters observed so far.
    // There's no mechanism in the current `HttpFilter` trait to plumb a
    // reset notification through to something that *can* write `StreamInfo`
    // (the filter manager would need to call `finalize`-like logic itself,
    // or `on_destroy` would need a callbacks parameter) — that's a trait
    // change, which is out of scope here. Today, a reset mid-response simply
    // never gets a `StreamInfo::llm` write; the "finalize on end_stream /
    // trailers" path above is the only one that fires.
}

#[cfg(test)]
mod tests {
    use super::*;

    use bytes::Bytes;
    use http::{HeaderValue, StatusCode};
    use std::sync::Arc;

    use proxy_http::filter::{BufferedBody, PerRouteConfig};
    use proxy_http::stream_info::StreamInfo;

    // --- test scaffolding ---------------------------------------------------

    /// A minimal `EncoderCallbacks` double: only `stream_info()` is ever
    /// exercised by this filter, so every other method is `unimplemented!()`
    /// — if the filter ever starts calling one of them (e.g. buffering via
    /// `add_encoded_data`), the test panics loudly instead of passing by
    /// accident.
    ///
    /// Rust note: the `StreamInfo` sits behind a `RefCell` because the real
    /// chain shares one instance between the filters and the router
    /// (`Rc<RefCell<StreamInfo>>`), so `stream_info()` returns a `RefMut`
    /// guard rather than a plain `&mut`. The double mirrors that shape; no
    /// `Rc` is needed here since nothing else holds a handle.
    struct TestCallbacks {
        stream_info: std::cell::RefCell<StreamInfo>,
        per_route_config: Option<Arc<dyn PerRouteConfig>>,
    }

    impl TestCallbacks {
        fn new() -> Self {
            TestCallbacks {
                stream_info: std::cell::RefCell::new(StreamInfo::default()),
                per_route_config: None,
            }
        }

        fn with_per_route_config(mut self, config: Arc<dyn PerRouteConfig>) -> Self {
            self.per_route_config = Some(config);
            self
        }

        /// Snapshot the LLM stats for assertions, so tests don't hold a
        /// `Ref` guard across a later filter call.
        fn llm(&self) -> proxy_http::LlmStats {
            self.stream_info.borrow().llm.clone()
        }
    }

    impl EncoderCallbacks for TestCallbacks {
        fn continue_encoding(&mut self) {
            unimplemented!("usage filter must not call continue_encoding")
        }
        fn add_encoded_data(&mut self, _data: Bytes, _streaming: bool) {
            unimplemented!("usage filter must never buffer via add_encoded_data")
        }
        fn inject_encoded_data_to_filter_chain(&mut self, _data: Bytes, _end_stream: bool) {
            unimplemented!("usage filter must not inject data")
        }
        fn encoding_buffer(&self) -> Option<&BufferedBody> {
            unimplemented!("usage filter must not consult the encoding buffer")
        }
        fn modify_encoding_buffer(&mut self, _f: &mut dyn FnMut(&mut BytesMut)) {
            unimplemented!("usage filter must not touch the encoding buffer")
        }
        /// Must be overridden, not inherited. `EncoderCallbacks` defaults this
        /// to `None`, so a double that merely *stores* a per-route config
        /// without returning it here sends every test down the no-override
        /// path — the per-route logic looks exercised while never running.
        fn per_route_config(&mut self) -> Option<Arc<dyn PerRouteConfig>> {
            self.per_route_config.clone()
        }
        fn stream_info(&mut self) -> std::cell::RefMut<'_, StreamInfo> {
            self.stream_info.borrow_mut()
        }
    }

    fn response_headers(content_type: &str) -> ResponseHeaders {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_str(content_type).unwrap(),
        );
        ResponseHeaders {
            status: StatusCode::OK,
            headers,
        }
    }

    fn filter_for(dialect: Dialect) -> UsageFilterInstance {
        UsageFilterInstance {
            dialect,
            mode: BodyMode::Inert,
            headers_at: None,
            last_chunk_at: None,
            time_to_first_byte: None,
            max_inter_chunk: None,
            response_chunks: 0,
            finalized: false,
        }
    }

    fn data_source(inline_string: &str) -> DynamicMessage {
        let desc = proxy_api::descriptor_pool()
            .get_message_by_name("envoy.config.core.v3.DataSource")
            .expect("DataSource is compiled into proxy-api");
        let mut msg = DynamicMessage::new(desc);
        msg.set_field_by_name(
            "inline_string",
            prost_reflect::Value::String(inline_string.to_string()),
        );
        msg
    }

    // --- behavior tests -------------------------------------------------------

    #[test]
    fn openai_json_body_split_across_several_chunks() {
        let mut filter = filter_for(Dialect::OpenAi);
        let mut cb = TestCallbacks::new();

        let mut headers = response_headers("application/json");
        assert_eq!(
            filter.encode_headers(&mut cb, &mut headers, false),
            FilterHeadersStatus::Continue
        );

        let body = br#"{"id":"x","usage":{"prompt_tokens":10,"completion_tokens":5}}"#;
        for (i, chunk) in body.chunks(7).enumerate() {
            let last = (i + 1) * 7 >= body.len();
            let mut data = Bytes::copy_from_slice(chunk);
            let status = filter.encode_data(&mut cb, &mut data, last);
            assert_eq!(status, FilterDataStatus::Continue);
        }

        let usage = cb.llm().usage.expect("usage should be found");
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 5);
    }

    #[test]
    fn openai_sse_stream_fed_byte_at_a_time() {
        let mut filter = filter_for(Dialect::OpenAi);
        let mut cb = TestCallbacks::new();

        let mut headers = response_headers("text/event-stream");
        filter.encode_headers(&mut cb, &mut headers, false);

        let stream = b"data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\
              data: {\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5}}\n\
              data: [DONE]\n";

        for (i, byte) in stream.iter().enumerate() {
            let last = i + 1 == stream.len();
            let mut data = Bytes::copy_from_slice(std::slice::from_ref(byte));
            let status = filter.encode_data(&mut cb, &mut data, last);
            assert_eq!(status, FilterDataStatus::Continue);
        }

        let usage = cb.llm().usage.expect("usage should be found");
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 5);
        assert_eq!(cb.llm().response_chunks, stream.len() as u64);
    }

    #[test]
    fn anthropic_sse_message_start_and_delta() {
        let mut filter = filter_for(Dialect::Anthropic);
        let mut cb = TestCallbacks::new();

        let mut headers = response_headers("text/event-stream");
        filter.encode_headers(&mut cb, &mut headers, false);

        let start = b"event: message_start\n\
                      data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}\n\n";
        let delta =
            b"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":15}}\n";

        let mut data1 = Bytes::copy_from_slice(start);
        filter.encode_data(&mut cb, &mut data1, false);
        let mut data2 = Bytes::copy_from_slice(delta);
        filter.encode_data(&mut cb, &mut data2, true);

        let usage = cb.llm().usage.expect("usage should be found");
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 15);
    }

    #[test]
    fn unknown_content_type_is_inert_and_always_continues() {
        let mut filter = filter_for(Dialect::OpenAi);
        let mut cb = TestCallbacks::new();

        let mut headers = response_headers("text/plain");
        assert_eq!(
            filter.encode_headers(&mut cb, &mut headers, false),
            FilterHeadersStatus::Continue
        );

        let mut data = Bytes::from_static(b"hello, this is not usage data");
        assert_eq!(
            filter.encode_data(&mut cb, &mut data, false),
            FilterDataStatus::Continue
        );

        let mut trailers = ResponseTrailers::default();
        assert_eq!(
            filter.encode_trailers(&mut cb, &mut trailers),
            FilterTrailersStatus::Continue
        );

        assert_eq!(cb.llm().usage, None);
    }

    #[test]
    fn json_content_type_with_parameters_still_parses_as_json() {
        let mut filter = filter_for(Dialect::OpenAi);
        let mut cb = TestCallbacks::new();

        let mut headers = response_headers("application/json; charset=utf-8");
        filter.encode_headers(&mut cb, &mut headers, false);

        let mut data =
            Bytes::from_static(br#"{"usage":{"prompt_tokens":1,"completion_tokens":2}}"#);
        filter.encode_data(&mut cb, &mut data, true);

        let usage = cb.llm().usage.expect("usage should be found");
        assert_eq!(usage.input_tokens, 1);
        assert_eq!(usage.output_tokens, 2);
    }

    #[test]
    fn oversized_json_body_yields_no_usage_not_a_partial_count() {
        let mut filter = filter_for(Dialect::OpenAi);
        let mut cb = TestCallbacks::new();

        let mut headers = response_headers("application/json");
        filter.encode_headers(&mut cb, &mut headers, false);

        // One chunk bigger than the cap, followed by the well-formed tail
        // that (if this were parsed at all) would carry real usage. If the
        // filter mistakenly kept a truncated prefix, this would produce a
        // parse error but *could* in principle still be Some via a lenient
        // parser — assert None explicitly, not just "not the real answer".
        let mut oversized = Bytes::from(vec![b' '; MAX_JSON_BODY_BYTES + 1]);
        filter.encode_data(&mut cb, &mut oversized, false);

        let mut tail =
            Bytes::from_static(br#"{"usage":{"prompt_tokens":1,"completion_tokens":1}}"#);
        filter.encode_data(&mut cb, &mut tail, true);

        assert_eq!(cb.llm().usage, None);
    }

    #[test]
    fn no_usage_in_response_is_none_not_zero() {
        let mut filter = filter_for(Dialect::OpenAi);
        let mut cb = TestCallbacks::new();

        let mut headers = response_headers("application/json");
        filter.encode_headers(&mut cb, &mut headers, false);

        let mut data = Bytes::from_static(br#"{"id":"x","choices":[]}"#);
        filter.encode_data(&mut cb, &mut data, true);

        assert_eq!(cb.llm().usage, None);
    }

    /// The four cost buckets are priced differently, so all four must survive
    /// the `TokenUsage` -> `LlmTokenUsage` conversion. A version of this
    /// filter that carried only input/output would still pass every other
    /// test in this file while making correct billing impossible.
    #[test]
    fn all_four_cost_buckets_cross_the_boundary() {
        let mut filter = filter_for(Dialect::Anthropic);
        let mut cb = TestCallbacks::new();

        let mut headers = response_headers("application/json");
        filter.encode_headers(&mut cb, &mut headers, false);

        let mut data = Bytes::from_static(
            br#"{"usage":{"input_tokens":10,"output_tokens":5,
                 "cache_read_input_tokens":80,"cache_creation_input_tokens":7}}"#,
        );
        filter.encode_data(&mut cb, &mut data, true);

        let usage = cb.llm().usage.expect("usage should be found");
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.cached_tokens, 80);
        assert_eq!(usage.cache_creation_tokens, 7);
        assert_eq!(usage.output_tokens, 5);
        assert_eq!(usage.total(), 102);
    }

    /// OpenAI reports cached tokens nested under `prompt_tokens_details` as a
    /// *subset* of `prompt_tokens`; the extractor breaks them out, and the
    /// filter must not re-merge them.
    #[test]
    fn openai_cached_tokens_arrive_broken_out() {
        let mut filter = filter_for(Dialect::OpenAi);
        let mut cb = TestCallbacks::new();

        let mut headers = response_headers("application/json");
        filter.encode_headers(&mut cb, &mut headers, false);

        let mut data = Bytes::from_static(
            br#"{"usage":{"prompt_tokens":100,"completion_tokens":20,
                 "prompt_tokens_details":{"cached_tokens":80}}}"#,
        );
        filter.encode_data(&mut cb, &mut data, true);

        let usage = cb.llm().usage.expect("usage should be found");
        assert_eq!(
            usage.input_tokens, 20,
            "prompt_tokens net of the cached part"
        );
        assert_eq!(usage.cached_tokens, 80);
        assert_eq!(usage.output_tokens, 20);
        assert_eq!(
            usage.total(),
            120,
            "must equal prompt_tokens + completion_tokens"
        );
    }

    #[test]
    fn encode_data_never_buffers() {
        let mut filter = filter_for(Dialect::OpenAi);
        let mut cb = TestCallbacks::new();

        let mut headers = response_headers("text/event-stream");
        filter.encode_headers(&mut cb, &mut headers, false);

        for i in 0..50 {
            let mut data = Bytes::from(format!("data: {{\"n\":{i}}}\n"));
            let status = filter.encode_data(&mut cb, &mut data, i == 49);
            assert_eq!(
                status,
                FilterDataStatus::Continue,
                "encode_data must always return Continue -- it must never buffer"
            );
        }
    }

    #[test]
    fn ttfb_and_max_inter_chunk_populate_as_chunks_arrive() {
        let mut filter = filter_for(Dialect::OpenAi);
        let mut cb = TestCallbacks::new();

        let mut headers = response_headers("text/event-stream");
        filter.encode_headers(&mut cb, &mut headers, false);
        assert_eq!(cb.llm().time_to_first_byte, None);
        assert_eq!(cb.llm().max_inter_chunk, None);

        let mut first = Bytes::from_static(b"data: {\"a\":1}\n");
        filter.encode_data(&mut cb, &mut first, false);
        // time_to_first_byte/max_inter_chunk are only written at finalize;
        // finalize the stream now to observe them.
        let mut second = Bytes::from_static(b"data: {\"b\":2}\n");
        filter.encode_data(&mut cb, &mut second, true);

        assert!(cb.llm().time_to_first_byte.is_some());
        assert!(cb.llm().max_inter_chunk.is_some());
    }

    // --- config parsing ---------------------------------------------------

    #[test]
    fn config_accepts_openai_case_insensitively() {
        for value in ["openai", "OpenAI", "OPENAI"] {
            let dialect = parse_config(&data_source(value)).expect("valid dialect");
            assert_eq!(dialect, Dialect::OpenAi);
        }
    }

    #[test]
    fn config_accepts_anthropic_case_insensitively() {
        for value in ["anthropic", "Anthropic", "ANTHROPIC"] {
            let dialect = parse_config(&data_source(value)).expect("valid dialect");
            assert_eq!(dialect, Dialect::Anthropic);
        }
    }

    #[test]
    fn config_rejects_unknown_dialect() {
        let err = parse_config(&data_source("gemini")).expect_err("unknown dialect must fail");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.inline_string");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn config_rejects_empty_dialect() {
        let err = parse_config(&data_source("")).expect_err("empty dialect must fail");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.inline_string");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn factory_creates_a_working_filter() {
        let factory = UsageFilterFactory;
        let instance_factory = factory
            .create(&data_source("openai"), &FactoryContext {})
            .expect("valid config builds a factory");
        let mut filter = instance_factory.create_filter();
        let mut cb = TestCallbacks::new();

        let mut headers = response_headers("application/json");
        assert_eq!(
            filter.encode_headers(&mut cb, &mut headers, false),
            FilterHeadersStatus::Continue
        );
        let mut data =
            Bytes::from_static(br#"{"usage":{"prompt_tokens":3,"completion_tokens":4}}"#);
        filter.encode_data(&mut cb, &mut data, true);

        let usage = cb.llm().usage.expect("usage should be found");
        assert_eq!(usage.input_tokens, 3);
        assert_eq!(usage.output_tokens, 4);
    }

    #[test]
    fn per_route_config_override_changes_the_dialect_used() {
        let mut filter = filter_for(Dialect::OpenAi);
        let override_cfg = Arc::new(UsagePerRouteConfig(Dialect::Anthropic));
        let mut cb = TestCallbacks::new().with_per_route_config(override_cfg);

        let mut headers = response_headers("application/json");
        assert_eq!(
            filter.encode_headers(&mut cb, &mut headers, false),
            FilterHeadersStatus::Continue
        );

        let mut data = Bytes::from_static(br#"{"usage":{"input_tokens":7,"output_tokens":9}}"#);
        filter.encode_data(&mut cb, &mut data, true);

        let usage = cb.llm().usage.expect("usage should be found");
        assert_eq!(usage.input_tokens, 7);
        assert_eq!(usage.output_tokens, 9);
    }

    #[test]
    fn parse_per_route_accepts_route_level_dialect() {
        let factory = UsageFilterFactory;
        let per_route = factory
            .parse_per_route(&data_source("anthropic"))
            .expect("valid per-route config");
        let dialect = per_route
            .as_any()
            .downcast_ref::<UsagePerRouteConfig>()
            .expect("UsagePerRouteConfig")
            .0;
        assert_eq!(dialect, Dialect::Anthropic);
    }
}
