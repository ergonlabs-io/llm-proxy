//! WP-11: the HTTP filter manager — drives the S2 iteration state machine over
//! the frozen [`crate::filter`] API and bridges it to the codec's
//! [`StreamHandler`] seam.
//!
//! # Scope of this chunk (chunk 1)
//!
//! This is the **buffered-model** core: for one downstream request it collects
//! the whole request body, runs the decoder chain (config order), hands the
//! result to an inner terminal [`StreamHandler`] (the router stand-in until
//! WP-13), then runs the encoder chain (**reverse** config order, S2.1) over the
//! response. It implements the parts of S2 whose mechanics are exercised without
//! streaming:
//!
//! - S2.1 ordering (decode forward, encode reverse);
//! - S2.2/S2.3 `Continue`, `StopIteration` header-hold + resume (via
//!   `continue_*()` or a `Continue` from the same filter's data callback), and
//!   the buffering statuses (which, in a fully-buffered model, all collapse to
//!   "hold until this filter continues");
//! - `add_*_data` / `*coding_buffer` / `modify_*_buffer` buffer APIs (S2.7);
//! - buffer-limit overflow → **413** (decode) / **500** (encode) (S2.2/S2.3).
//!
//! Deferred to later chunks (each callback that isn't fully wired says so):
//! streaming / early-flush and watermark backpressure; `send_local_reply`
//! routed through the encoder chain (S2.5); 1xx (S2.6);
//! `inject_*_to_filter_chain` and `ContinueAndDontEndStream` (S2.7); lazy route
//! resolution + cache (S2.8, needs the WP-12 route table). The ~60-case S2
//! conformance suite (chunk 2) is what will pin every corner.
//!
//! # The borrow problem (and why this compiles without `unsafe`)
//!
//! A filter callback receives `&mut dyn DecoderCallbacks` — the manager — while
//! the manager is also holding `&mut filters[i]` to make the call. Envoy uses
//! raw back-pointers here. We instead **split storage**: the filter `Vec` and
//! the mutable [`ChainCtx`] (buffers, stream info, continuation flags) are
//! distinct fields, and the message head is passed as its own `&mut`. So one
//! call site borrows three *disjoint* things — `&mut filters[i]`, `&mut head`,
//! and a callbacks adapter that borrows only `&mut ctx` — which the borrow
//! checker accepts. It's sound because the callbacks only ever *record* state in
//! `ctx` (continue flags, appended buffer bytes) that the driver acts on **after
//! the callback returns**; a callback never re-enters another filter.

use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use http::HeaderMap;
use http_body_util::{BodyExt, StreamBody};

use proxy_config::ir::RouteEntry;

use crate::filter::{
    BufferedBody, DecoderCallbacks, EncoderCallbacks, FilterDataStatus, FilterHeadersStatus,
    FilterInstanceFactory, HeaderMutationFn, HttpFilter, RequestHeaders, RequestTrailers,
    ResponseHeaders, ResponseTrailers,
};
use crate::handler::{
    local_boxed, BodyError, HttpRequestParts, HttpResponseParts, StreamBody as SeamBody,
    StreamHandler,
};
use crate::stream_info::StreamInfo;

/// Default per-direction buffer limit (Envoy's
/// `per_connection_buffer_limit_bytes` default is 1 MiB). Overflow of a filter
/// that requested buffering yields 413 on decode / 500 on encode.
pub const DEFAULT_BUFFER_LIMIT: usize = 1 << 20;

/// A [`StreamHandler`] that runs a request through an HTTP filter chain before
/// (and the response after) an inner terminal handler. One of these is built per
/// HTTP connection manager (see `build_hcm_handler` in proxy-core) and reused
/// across every request on the connection; a fresh set of per-stream filter
/// instances is created for each request (S2.1: "instances are per-stream").
pub struct FilterChainHandler {
    /// Config-order factories; `create_filter()` mints one instance per stream.
    factories: Vec<Arc<dyn FilterInstanceFactory>>,
    /// The router stand-in: consumes the (decoded) request, produces a response.
    terminal: Rc<dyn StreamHandler>,
    buffer_limit: usize,
}

impl FilterChainHandler {
    pub fn new(
        factories: Vec<Arc<dyn FilterInstanceFactory>>,
        terminal: Rc<dyn StreamHandler>,
    ) -> Self {
        Self {
            factories,
            terminal,
            buffer_limit: DEFAULT_BUFFER_LIMIT,
        }
    }

    pub fn with_buffer_limit(mut self, limit: usize) -> Self {
        self.buffer_limit = limit;
        self
    }
}

impl StreamHandler for FilterChainHandler {
    fn handle<'a>(
        &'a self,
        req: HttpRequestParts,
    ) -> Pin<Box<dyn Future<Output = HttpResponseParts> + 'a>> {
        Box::pin(async move {
            // Rust note: a fresh, `!Send` instance vector per request — filters
            // may freely hold `Rc`/`RefCell` (ADR-0003).
            let filters: Vec<Box<dyn HttpFilter>> =
                self.factories.iter().map(|f| f.create_filter()).collect();
            let mgr = FilterManager {
                filters,
                ctx: ChainCtx::new(),
                terminal: self.terminal.as_ref(),
                buffer_limit: self.buffer_limit,
            };
            mgr.run(req).await
        })
    }
}

/// Per-direction iteration bookkeeping the callbacks record into and the driver
/// reads back after each callback returns.
#[derive(Default)]
struct DirectionState {
    /// Filter-manager buffer for this direction (S2.7).
    buffer: BufferedBody,
    /// Set by `continue_decoding()` / `continue_encoding()`; the driver clears
    /// it once observed.
    continue_requested: bool,
}

/// Split-storage counterpart to the filter `Vec`: everything a callback may
/// touch. Kept separate from the filters so a callback adapter can borrow this
/// while the driver still holds `&mut filters[i]` (see the module doc).
struct ChainCtx {
    decode: DirectionState,
    encode: DirectionState,
    stream_info: StreamInfo,
    /// Cached route (S2.8). TODO(WP-11 chunk 3 / WP-12): lazy resolution against
    /// the route table; always `None` here.
    route: Option<Arc<RouteEntry>>,
}

impl ChainCtx {
    fn new() -> Self {
        Self {
            decode: DirectionState::default(),
            encode: DirectionState::default(),
            stream_info: StreamInfo::default(),
            route: None,
        }
    }
}

/// One request's worth of filter-chain execution. Consumed by [`Self::run`].
struct FilterManager<'t> {
    filters: Vec<Box<dyn HttpFilter>>,
    ctx: ChainCtx,
    terminal: &'t dyn StreamHandler,
    buffer_limit: usize,
}

impl FilterManager<'_> {
    async fn run(self, req: HttpRequestParts) -> HttpResponseParts {
        let FilterManager {
            mut filters,
            mut ctx,
            terminal,
            buffer_limit,
        } = self;

        // --- collect the request body (buffered model) ---
        let (mut head, req_trailers, mut body) = match collect_request(req).await {
            Ok(parts) => parts,
            // A downstream body read error is a client problem: 400. (Streaming
            // will surface this mid-flight instead; chunk 1 sees it up front.)
            Err(()) => {
                return synth_response(http::StatusCode::BAD_REQUEST, "invalid request body")
            }
        };

        // --- decode chain (config order) ---
        if let Err(status) = drive_decode(
            &mut filters,
            &mut ctx,
            buffer_limit,
            &mut head,
            &mut body,
            req_trailers.as_ref(),
        ) {
            return synth_response(status, "request rejected by filter chain");
        }

        // Anything filters appended via `add_decoded_data` rides along to the
        // terminal handler ahead of the original body.
        let decoded_body = join_buffer(&ctx.decode.buffer, &body);

        // --- terminal handler (router stand-in) ---
        let terminal_req = HttpRequestParts {
            head,
            body: bytes_to_seam_body(decoded_body, req_trailers.map(|t| t.0)),
        };
        let resp = terminal.handle(terminal_req).await;

        // --- collect + encode the response (reverse config order, S2.1) ---
        let (mut resp_head, resp_trailers, resp_body) = match collect_response(resp).await {
            Ok(parts) => parts,
            Err(()) => {
                return synth_response(
                    http::StatusCode::INTERNAL_SERVER_ERROR,
                    "upstream body error",
                )
            }
        };
        let mut resp_body = resp_body;

        if let Err(status) = drive_encode(
            &mut filters,
            &mut ctx,
            buffer_limit,
            &mut resp_head,
            &mut resp_body,
            resp_trailers.as_ref(),
        ) {
            return synth_response(status, "response rejected by filter chain");
        }

        let encoded_body = join_buffer(&ctx.encode.buffer, &resp_body);

        // Per-stream teardown, reverse creation order (S2.1).
        for filter in filters.iter_mut().rev() {
            filter.on_destroy();
        }

        HttpResponseParts {
            head: resp_head,
            body: bytes_to_seam_body(encoded_body, resp_trailers.map(|t| t.0)),
        }
    }
}

/// Drive the decoder chain over a fully-buffered request. Returns `Err(status)`
/// if a filter's buffering overflowed `buffer_limit` (→ 413) — the only failure
/// this chunk raises. `body` may be mutated in place by `decode_data`.
///
/// The pointer machine (S2.2/S2.3): walk filters forward delivering headers;
/// when a filter holds (`StopIteration`/buffer/stop-all), deliver the buffered
/// data to *that same* filter (S2.2: its data callbacks still fire); if it then
/// continues (returns `Continue` from `decode_data` or calls
/// `continue_decoding()`), resume header delivery at the next filter. Once the
/// header phase completes, every filter that continued on headers but has not
/// yet seen the body gets it, in config order.
///
/// A `data_consumed` guard makes each filter's `decode_data` fire **exactly
/// once**: a filter that took its data early (to resolve a header-hold) is
/// skipped by the trailing data phase.
///
/// Chunk-1 simplification (documented; the streaming chunk fixes it): a
/// held filter takes its data slightly before earlier filters in wall-clock
/// order. Since the body is a single buffered chunk, the observable
/// per-filter effect — each `decode_data` called once, in config order — is
/// preserved. A hold that never resolves synchronously (async buffering /
/// local reply) is chunk 3; here it simply stops progression past that filter.
fn drive_decode(
    filters: &mut [Box<dyn HttpFilter>],
    ctx: &mut ChainCtx,
    buffer_limit: usize,
    head: &mut RequestHeaders,
    body: &mut Bytes,
    trailers: Option<&RequestTrailers>,
) -> Result<(), http::StatusCode> {
    let end_stream_on_headers = body.is_empty() && trailers.is_none();
    let mut data_consumed = vec![false; filters.len()];
    // `header_reach`: one past the last filter that received (and continued on)
    // headers. Filters `[0, header_reach)` get data in the trailing phase.
    let mut header_reach = 0;
    let mut idx = 0;
    while idx < filters.len() {
        // Split borrow: `&mut filters[idx]`, `&mut *head`, and an adapter over
        // `&mut *ctx` are three disjoint borrows (module doc).
        let mut cb = DecoderCallbacksAdapter { ctx };
        let status = filters[idx].decode_headers(&mut cb, head, end_stream_on_headers);
        // A filter that buffered via add_decoded_data must not exceed the limit.
        if ctx.decode.buffer.0.len() > buffer_limit {
            return Err(http::StatusCode::PAYLOAD_TOO_LARGE);
        }

        match status {
            FilterHeadersStatus::Continue | FilterHeadersStatus::ContinueAndDontEndStream => {
                // ContinueAndDontEndStream: TODO(WP-11 chunk 3) forward with
                // end_stream=false + require inject_*; treated as Continue here.
                idx += 1;
                header_reach = idx;
            }
            FilterHeadersStatus::StopIteration
            | FilterHeadersStatus::StopAllIterationAndBuffer
            | FilterHeadersStatus::StopAllIterationAndWatermark => {
                // Headers held at `idx`. Deliver the (buffered) data to this same
                // filter; if it continues, resume header delivery at the next.
                let continued = deliver_decode_data(
                    filters,
                    ctx,
                    buffer_limit,
                    idx,
                    body,
                    trailers,
                    &mut data_consumed,
                )?;
                if continued {
                    idx += 1;
                    header_reach = idx;
                } else {
                    break;
                }
            }
        }
    }

    // Trailing data phase: filters that continued on headers but haven't yet
    // seen the body, in config order.
    for i in 0..header_reach {
        if data_consumed[i] {
            continue;
        }
        deliver_decode_data(
            filters,
            ctx,
            buffer_limit,
            i,
            body,
            trailers,
            &mut data_consumed,
        )?;
    }
    Ok(())
}

/// Deliver the buffered body (and, if the filter continues, trailers) to filter
/// `idx` exactly once. Returns whether it continued. Marks `data_consumed[idx]`.
fn deliver_decode_data(
    filters: &mut [Box<dyn HttpFilter>],
    ctx: &mut ChainCtx,
    buffer_limit: usize,
    idx: usize,
    body: &mut Bytes,
    trailers: Option<&RequestTrailers>,
    data_consumed: &mut [bool],
) -> Result<bool, http::StatusCode> {
    data_consumed[idx] = true;
    ctx.decode.continue_requested = false;
    let end_stream = trailers.is_none();
    let mut cb = DecoderCallbacksAdapter { ctx };
    let status = filters[idx].decode_data(&mut cb, body, end_stream);
    if ctx.decode.buffer.0.len() > buffer_limit {
        return Err(http::StatusCode::PAYLOAD_TOO_LARGE);
    }
    let continued = matches!(status, FilterDataStatus::Continue) || ctx.decode.continue_requested;

    if continued {
        if let Some(t) = trailers {
            let mut cb = DecoderCallbacksAdapter { ctx };
            let mut owned = RequestTrailers(t.0.clone());
            let _ = filters[idx].decode_trailers(&mut cb, &mut owned);
        }
    }
    Ok(continued)
}

/// Encoder pass over the response, walking filters in **reverse** config order
/// (S2.1). Overflow of a buffering filter here → 500.
///
/// Chunk-1 simplification: this delivers headers to every filter, then data +
/// trailers to every filter, honoring `add_encoded_data`/buffer-limit but not
/// yet the encode-side header-hold-then-resume-via-data mechanics that
/// [`drive_decode`] implements. Encode holds and `send_local_reply`-during-encode
/// (S2.5) land with the chunk-2 conformance suite.
fn drive_encode(
    filters: &mut [Box<dyn HttpFilter>],
    ctx: &mut ChainCtx,
    buffer_limit: usize,
    head: &mut ResponseHeaders,
    body: &mut Bytes,
    trailers: Option<&ResponseTrailers>,
) -> Result<(), http::StatusCode> {
    let end_stream_on_headers = body.is_empty() && trailers.is_none();
    // Reverse config order.
    let order: Vec<usize> = (0..filters.len()).rev().collect();
    for &idx in &order {
        let mut cb = EncoderCallbacksAdapter { ctx };
        let _ = filters[idx].encode_headers(&mut cb, head, end_stream_on_headers);
        if ctx.encode.buffer.0.len() > buffer_limit {
            return Err(http::StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
    if !(body.is_empty() && trailers.is_none()) {
        for &idx in &order {
            let mut cb = EncoderCallbacksAdapter { ctx };
            let _ = filters[idx].encode_data(&mut cb, body, trailers.is_none());
            if ctx.encode.buffer.0.len() > buffer_limit {
                return Err(http::StatusCode::INTERNAL_SERVER_ERROR);
            }
            if let Some(t) = trailers {
                let mut cb = EncoderCallbacksAdapter { ctx };
                let mut owned = ResponseTrailers(t.0.clone());
                let _ = filters[idx].encode_trailers(&mut cb, &mut owned);
            }
        }
    }
    Ok(())
}

// --- callback adapters -----------------------------------------------------

/// Borrows only [`ChainCtx`]; never the filter list (module doc).
struct DecoderCallbacksAdapter<'c> {
    ctx: &'c mut ChainCtx,
}

impl DecoderCallbacks for DecoderCallbacksAdapter<'_> {
    fn send_local_reply(
        &mut self,
        _code: http::StatusCode,
        _body: &str,
        _modify_headers: Option<HeaderMutationFn>,
        details: &str,
    ) {
        // TODO(WP-11 chunk 3, S2.5): synthesize + run through the encoder chain,
        // or reset if headers already sent. For now just record intent.
        self.ctx.stream_info.is_local_reply = true;
        self.ctx.stream_info.response_code_details = Some(details.to_string());
    }

    fn continue_decoding(&mut self) {
        self.ctx.decode.continue_requested = true;
    }

    fn add_decoded_data(&mut self, data: Bytes, _streaming: bool) {
        self.ctx.decode.buffer.0.extend_from_slice(&data);
    }

    fn inject_decoded_data_to_filter_chain(&mut self, _data: Bytes, _end_stream: bool) {
        // TODO(WP-11 chunk 3, S2.7): out-of-callback injection to subsequent
        // filters. Needs the streaming driver.
        unimplemented!("inject_decoded_data_to_filter_chain lands in WP-11 chunk 3")
    }

    fn decoding_buffer(&self) -> Option<&BufferedBody> {
        if self.ctx.decode.buffer.0.is_empty() {
            None
        } else {
            Some(&self.ctx.decode.buffer)
        }
    }

    fn modify_decoding_buffer(&mut self, f: &mut dyn FnMut(&mut BytesMut)) {
        f(&mut self.ctx.decode.buffer.0);
    }

    fn route(&self) -> Option<Arc<RouteEntry>> {
        // TODO(WP-11 chunk 3 / WP-12): lazy resolution against the route table.
        self.ctx.route.clone()
    }

    fn clear_route_cache(&mut self) {
        self.ctx.route = None;
    }

    fn stream_info(&mut self) -> &mut StreamInfo {
        &mut self.ctx.stream_info
    }
}

/// Encoder mirror of [`DecoderCallbacksAdapter`].
struct EncoderCallbacksAdapter<'c> {
    ctx: &'c mut ChainCtx,
}

impl EncoderCallbacks for EncoderCallbacksAdapter<'_> {
    fn continue_encoding(&mut self) {
        self.ctx.encode.continue_requested = true;
    }

    fn add_encoded_data(&mut self, data: Bytes, _streaming: bool) {
        self.ctx.encode.buffer.0.extend_from_slice(&data);
    }

    fn inject_encoded_data_to_filter_chain(&mut self, _data: Bytes, _end_stream: bool) {
        unimplemented!("inject_encoded_data_to_filter_chain lands in WP-11 chunk 3")
    }

    fn encoding_buffer(&self) -> Option<&BufferedBody> {
        if self.ctx.encode.buffer.0.is_empty() {
            None
        } else {
            Some(&self.ctx.encode.buffer)
        }
    }

    fn modify_encoding_buffer(&mut self, f: &mut dyn FnMut(&mut BytesMut)) {
        f(&mut self.ctx.encode.buffer.0);
    }

    fn stream_info(&mut self) -> &mut StreamInfo {
        &mut self.ctx.stream_info
    }
}

// --- body plumbing ---------------------------------------------------------

/// Collect a request into head + optional trailers + buffered body bytes.
async fn collect_request(
    req: HttpRequestParts,
) -> Result<(RequestHeaders, Option<RequestTrailers>, Bytes), ()> {
    let HttpRequestParts { head, body } = req;
    let collected = body.collect().await.map_err(|_| ())?;
    let trailers = collected.trailers().cloned().map(RequestTrailers);
    Ok((head, trailers, collected.to_bytes()))
}

async fn collect_response(
    resp: HttpResponseParts,
) -> Result<(ResponseHeaders, Option<ResponseTrailers>, Bytes), ()> {
    let HttpResponseParts { head, body } = resp;
    let collected = body.collect().await.map_err(|_| ())?;
    let trailers = collected.trailers().cloned().map(ResponseTrailers);
    Ok((head, trailers, collected.to_bytes()))
}

/// Prepend a filter-manager buffer (bytes added via `add_*_data`) to the
/// original body. In the common case the buffer is empty and this is just a
/// clone of `body`.
fn join_buffer(buffer: &BufferedBody, body: &Bytes) -> Bytes {
    if buffer.0.is_empty() {
        body.clone()
    } else {
        let mut out = BytesMut::with_capacity(buffer.0.len() + body.len());
        out.extend_from_slice(&buffer.0);
        out.extend_from_slice(body);
        out.freeze()
    }
}

/// Build a [`SeamBody`] carrying `bytes` as a single data frame plus optional
/// trailers — faithfully preserving trailers across the seam.
fn bytes_to_seam_body(bytes: Bytes, trailers: Option<HeaderMap>) -> SeamBody {
    use hyper::body::Frame;
    let mut frames: Vec<Result<Frame<Bytes>, BodyError>> = Vec::new();
    if !bytes.is_empty() {
        frames.push(Ok(Frame::data(bytes)));
    }
    if let Some(t) = trailers {
        frames.push(Ok(Frame::trailers(t)));
    }
    local_boxed(StreamBody::new(futures::stream::iter(frames)))
}

/// A minimal synthesized response for the failure paths this chunk raises
/// (buffer overflow, body read errors). Real local replies (S2.5) are chunk 3.
fn synth_response(status: http::StatusCode, message: &str) -> HttpResponseParts {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    let body = format!("{message}\n");
    HttpResponseParts {
        head: ResponseHeaders { status, headers },
        body: bytes_to_seam_body(Bytes::from(body), None),
    }
}

#[cfg(test)]
mod tests;
