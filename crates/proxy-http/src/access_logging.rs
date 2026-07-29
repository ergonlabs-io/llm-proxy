//! WP-24 chunk 3 (relocated): turns the parsed `AccessLogIR`/`FormatString`
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
//! WP-33/34 usage filter, notably) was therefore invisible to access logs.
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
use std::task::{Context, Poll};
use std::time::{Instant, SystemTime};

use bytes::Bytes;
use http::HeaderMap;
use hyper::body::{Body, Frame};

use proxy_config::ir::{AccessLogFilterIR, AccessLogFormat, AccessLogIR, ComparisonOp};
use proxy_observability::access_log::{render, FormatString, LlmTokens, LogContext};
use proxy_observability::sink::{AccessLogWriter, SinkRegistry};

use crate::handler::{BodyError, StreamBody};
use crate::stream_info::StreamInfo;

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

    /// Ground rule #1 note: every `AccessLogFilterIR` variant is matched
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
        self.sink.write_line(&self.render_line(ctx));
        // `FileSink::write_line` only writes into its `BufWriter` --
        // stdout/stderr sinks flush themselves per line, but a file sink
        // doesn't (see its own doc: buffered for throughput). Flushing
        // here trades a little of that throughput for every access-log
        // line actually being durable (and readable by anything tailing
        // the file) as soon as the request it describes finishes, rather
        // than sitting in an in-process buffer indefinitely -- there's no
        // periodic-flush component in the data plane yet to do this any
        // other way.
        self.sink.flush();
    }
}

/// Render Envoy's `json_format`: every field's value is itself a rendered
/// [`FormatString`] (chunk 1), turned into a JSON string value. Envoy's real
/// `json_format` supports typed (numeric/bool/nested) values via shortcuts
/// this IR doesn't carry -- `AccessLogFormat::Json` is
/// `Vec<(String, FormatString)>`, always string-typed -- so every value
/// renders as a JSON string here, never a bare number/bool/object. That's a
/// known, disclosed gap (ground rule #1), not a silent one: nothing in the
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

/// `%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%` (the default access-log format's own
/// path field) falls back to a `:PATH` pseudo-header `header_lookup` can
/// never resolve (see its doc in `proxy_observability::access_log`) --
/// populating the *primary* header here, the same normal header name real
/// Envoy sets on a `prefix_rewrite`, is what makes that default format
/// usable at all for the path, without touching the (frozen) formatter
/// itself.
///
/// Rust note: takes `&HeaderMap` and clones rather than mutating in place --
/// every call site needs an independent snapshot (the caller's own headers
/// keep flowing through the rest of the pipeline unmodified).
pub(crate) fn snapshot_request_headers(headers: &HeaderMap, path: &str) -> HeaderMap {
    let mut snapshot = headers.clone();
    if !snapshot.contains_key("x-envoy-original-path") {
        if let Ok(v) = http::HeaderValue::from_str(path) {
            snapshot.insert("x-envoy-original-path", v);
        }
    }
    snapshot
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
    pub(crate) request_headers: HeaderMap,
    pub(crate) response_headers: HeaderMap,
    pub(crate) response_code: u16,
    pub(crate) downstream_remote_address: String,
}

/// Wraps a response [`StreamBody`] so that -- regardless of whether the
/// stream completes normally, errors, or is simply dropped mid-flight (a
/// disconnecting client, or an outer combinator like `GuardedBody`/
/// `IdleTimeoutBody` giving up on it) -- exactly one access-log line is
/// rendered and written per configured logger, using the *final* byte count
/// and a duration covering the whole stream.
///
/// This is the seam WP-24 chunk 3 exists for: logging when *response
/// headers* are produced (the naive place to hook) is wrong for every
/// streamed LLM response -- the body (the actual tokens) is what takes the
/// time and carries the bytes; headers arrive almost immediately. Wrapping
/// the body itself, the same way `GuardedBody`/`IdleTimeoutBody` already do
/// for the S5/S4 concerns, is what lets this observe the real end of the
/// stream.
///
/// `LoggingBody` wraps the OUTERMOST response body -- see
/// `FilterChainHandler::handle`'s doc -- specifically OUTSIDE
/// `filter_manager::StreamingEncoder`, not nested inside the router's own
/// response like the pre-relocation design had it. That ordering is the
/// entire point of this module living here rather than under `router`: a
/// `StreamingEncoder(LoggingBody(...))` nesting renders the log line the
/// moment the router's body ends, before the encode filter chain's own
/// end-of-stream callback has run, which makes anything an encode filter
/// records at stream end (e.g. the WP-33/34 usage filter's token counts)
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
}

impl LoggingBody {
    pub(crate) fn new(inner: StreamBody, ctx: AccessLogContext) -> Self {
        Self {
            inner,
            bytes_sent: 0,
            trailers: HeaderMap::new(),
            ctx: Some(ctx),
        }
    }

    fn finish(&mut self) {
        let Some(ctx) = self.ctx.take() else {
            // Already logged (`poll_frame` beat `Drop` to it, or vice versa).
            return;
        };

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
        ) = {
            let mut info = ctx.stream_info.borrow_mut();
            info.bytes_sent = self.bytes_sent;
            // WP-33: `LlmTokenUsage` -> `LlmTokens` field-for-field --
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
            )
        };

        let log_ctx = LogContext {
            start_time: ctx.start_time,
            request_headers: &ctx.request_headers,
            response_headers: &ctx.response_headers,
            response_trailers: &self.trailers,
            protocol: protocol.as_deref(),
            response_code: Some(ctx.response_code),
            response_flags: &response_flags,
            duration: Some(ctx.start_instant.elapsed()),
            bytes_received,
            bytes_sent: self.bytes_sent,
            upstream_host: upstream_host.as_deref(),
            upstream_cluster: upstream_cluster.as_deref(),
            downstream_remote_address: Some(&ctx.downstream_remote_address),
            llm_tokens,
            llm_ttft,
        };
        for logger in ctx.loggers.iter() {
            logger.log(&log_ctx);
        }
    }
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
                if let Some(data) = frame.data_ref() {
                    this.bytes_sent += data.len() as u64;
                }
                if let Some(trailers) = frame.trailers_ref() {
                    this.trailers = trailers.clone();
                }
            }
            // Both a clean end-of-stream and an error are terminal for
            // logging purposes: either way nothing more will ever flow
            // through this body, so this is the last chance to observe the
            // final byte count before the caller (or `Drop`) moves on.
            Poll::Ready(None) | Poll::Ready(Some(Err(_))) => this.finish(),
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
        // end-of-stream/error through `poll_frame`. `finish` is idempotent
        // (`ctx.take()`), so this is a no-op if `poll_frame` already logged.
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
    /// line, proving the WP-33 token/TTFT operators reach the real access
    /// log through the same path as `bytes_sent` -- not just through
    /// `access_log::render` in isolation.
    async fn render_one(llm: crate::stream_info::LlmStats) -> String {
        let capture = Arc::new(CaptureSink::default());
        let fmt = parse_format(
            "%LLM_INPUT_TOKENS% %LLM_CACHED_TOKENS% %LLM_CACHE_CREATION_TOKENS% %LLM_OUTPUT_TOKENS% %LLM_TOTAL_TOKENS% %LLM_TTFT%",
        )
        .unwrap();
        let logger = AccessLoggerRuntime {
            sink: capture.clone() as Arc<dyn AccessLogWriter>,
            format: AccessLogFormat::Text(fmt),
            filter: None,
        };

        let mut stream_info = StreamInfo::default();
        stream_info.llm = llm;

        let ctx = AccessLogContext {
            loggers: Rc::new(vec![logger]),
            stream_info: Rc::new(RefCell::new(stream_info)),
            start_time: SystemTime::now(),
            start_instant: Instant::now(),
            request_headers: HeaderMap::new(),
            response_headers: HeaderMap::new(),
            response_code: StatusCode::OK.as_u16(),
            downstream_remote_address: "127.0.0.1:0".to_string(),
        };

        let body = local_boxed(
            Full::new(Bytes::from_static(b"hi"))
                .map_err(|infallible: std::convert::Infallible| match infallible {}),
        );
        let logging_body = LoggingBody::new(body, ctx);
        // Drain to end-of-stream, which is what triggers `finish()`.
        let _ = logging_body.collect().await.unwrap();

        let mut lines = capture.0.lock().unwrap();
        assert_eq!(lines.len(), 1, "expected exactly one rendered line");
        lines.remove(0)
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
            time_to_first_byte: Some(std::time::Duration::from_millis(250)),
            max_inter_chunk: None,
            response_chunks: 1,
        };
        assert_eq!(render_one(llm).await, "11 22 33 44 110 250");
    }

    #[tokio::test]
    async fn absent_llm_stats_render_dash_not_zero() {
        // WP-33: a stream that never populated `StreamInfo::llm` (a non-LLM
        // route, or a provider response with no usage) must log `-`, not a
        // confident-looking `0` -- these numbers feed billing.
        assert_eq!(
            render_one(crate::stream_info::LlmStats::default()).await,
            "- - - - - -"
        );
    }
}
