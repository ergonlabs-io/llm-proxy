//! WP-24 chunk 3: turns the parsed `AccessLogIR`/`FormatString` (chunks 1-2,
//! `proxy_observability::access_log`/`sink`) into real per-request log
//! lines. Two pieces:
//!
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
use proxy_observability::access_log::{render, FormatString, LogContext};
use proxy_observability::sink::{AccessLogWriter, SinkRegistry};

use crate::handler::{BodyError, StreamBody};
use crate::stream_info::StreamInfo;

/// One configured logger, resolved at HCM-bind time (mirrors
/// `proxy-core::listener::build_listener_hcm`'s own "compiled once, rebuilt
/// only when the snapshot version changes" cadence -- a fresh
/// `RouterHandler`, and so a fresh set of these, is built on every rebuild).
pub(super) struct AccessLoggerRuntime {
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
    pub(super) fn build_all(
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

/// Everything [`LoggingBody`] needs to render + write a line once the
/// response stream ends (or is dropped mid-stream) -- assembled once, in
/// `RouterHandler::handle`, before the body starts streaming to the
/// downstream client.
pub(super) struct AccessLogContext {
    pub(super) loggers: Rc<Vec<AccessLoggerRuntime>>,
    pub(super) stream_info: Rc<RefCell<StreamInfo>>,
    pub(super) start_time: SystemTime,
    pub(super) start_instant: Instant,
    pub(super) request_headers: HeaderMap,
    pub(super) response_headers: HeaderMap,
    pub(super) response_code: u16,
    pub(super) downstream_remote_address: String,
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
/// stream. `LoggingBody` wraps *outermost* (see `RouterHandler::handle`), so
/// it sees the stream end after those two have already run, not before.
///
/// Rust note: `ctx` is `Option<AccessLogContext>` purely so `finish` can be
/// called from either `poll_frame` (the common case: the stream ends or
/// errors while still being polled) or `Drop` (the stream is abandoned
/// without ever being polled to completion) and only actually log once,
/// without a separate "have I already logged" bool.
pub(super) struct LoggingBody {
    inner: StreamBody,
    bytes_sent: u64,
    trailers: HeaderMap,
    ctx: Option<AccessLogContext>,
}

impl LoggingBody {
    pub(super) fn new(inner: StreamBody, ctx: AccessLogContext) -> Self {
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
        let (response_flags, upstream_host, upstream_cluster, protocol, bytes_received) = {
            let mut info = ctx.stream_info.borrow_mut();
            info.bytes_sent = self.bytes_sent;
            (
                info.response_flags().to_vec(),
                info.upstream_host.clone(),
                info.upstream_cluster.clone(),
                info.protocol.clone(),
                info.bytes_received,
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

/// Wraps the *request* body being forwarded upstream, incrementing
/// `stream_info`'s `bytes_received` running total as frames stream through
/// -- the streaming-body counterpart of the buffered/retry path, which
/// already knows its exact length up front from `.collect()`.
pub(super) struct CountingRequestBody {
    inner: StreamBody,
    stream_info: Rc<RefCell<StreamInfo>>,
}

impl CountingRequestBody {
    pub(super) fn new(inner: StreamBody, stream_info: Rc<RefCell<StreamInfo>>) -> Self {
        Self { inner, stream_info }
    }
}

impl Body for CountingRequestBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_frame(cx);
        if let Poll::Ready(Some(Ok(frame))) = &poll {
            if let Some(data) = frame.data_ref() {
                this.stream_info.borrow_mut().bytes_received += data.len() as u64;
            }
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
