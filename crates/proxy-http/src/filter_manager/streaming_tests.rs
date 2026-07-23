//! WP-11 chunk 3 tests: the streaming encode path. Chunk 1's `tests.rs` pins
//! the decode-side (still buffered) mechanics; these pin the encode-side
//! [`StreamingEncoder`] state machine — frame-by-frame delivery, reverse
//! config order, buffering/release, trailers-behind-data (S2.4), buffer
//! overflow mid-stream, the header-hold gotcha applied to encode, and
//! `on_destroy` timing now that it's driven by `Drop`.

use std::cell::RefCell;
use std::rc::Rc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use http_body_util::BodyExt;

use super::*;
use crate::filter::{FilterTrailersStatus, RequestHeaders};
use crate::handler::{HttpRequestParts, HttpResponseParts};

/// Shared call log, same convention as `tests.rs`'s `ProbeFilter`.
type Log = Rc<RefCell<Vec<String>>>;

fn log_of() -> Log {
    Rc::new(RefCell::new(Vec::new()))
}

/// A configurable encode-side probe filter. Decode callbacks are all
/// pass-through (untested here; chunk 1 covers decode).
struct ProbeFilter {
    name: &'static str,
    log: Log,
    encode_headers_status: FilterHeadersStatus,
    /// Returned from `encode_data`, unless `release_on_end_stream` overrides it.
    encode_data_status: FilterDataStatus,
    /// Models "buffer until end-of-stream, then release": `encode_data`
    /// returns `Continue` when `end_stream` is true regardless of
    /// `encode_data_status`.
    release_on_end_stream: bool,
    /// Bytes appended via `add_encoded_data` from `encode_data`.
    add_encoded_in_data: Option<Bytes>,
    /// Applied to `data` in place during `encode_data` (e.g. uppercasing).
    rewrite: Option<fn(&mut Bytes)>,
}

impl ProbeFilter {
    fn new(name: &'static str, log: Log) -> Self {
        Self {
            name,
            log,
            encode_headers_status: FilterHeadersStatus::Continue,
            encode_data_status: FilterDataStatus::Continue,
            release_on_end_stream: false,
            add_encoded_in_data: None,
            rewrite: None,
        }
    }

    fn record(&self, what: &str) {
        self.log.borrow_mut().push(format!("{}:{what}", self.name));
    }
}

impl HttpFilter for ProbeFilter {
    fn encode_headers(
        &mut self,
        _cb: &mut dyn EncoderCallbacks,
        _headers: &mut ResponseHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        self.record("encode_headers");
        self.encode_headers_status
    }

    fn encode_data(
        &mut self,
        cb: &mut dyn EncoderCallbacks,
        data: &mut Bytes,
        end_stream: bool,
    ) -> FilterDataStatus {
        // Rust note: embedding the payload (rather than just the callback
        // name) in the log lets tests distinguish real frames from the
        // end-of-stream flush's empty data callback by content, without a
        // separate bookkeeping channel.
        self.record(&format!(
            "encode_data:{}:end={end_stream}",
            String::from_utf8_lossy(data)
        ));
        // `.take()`: a real filter injects extra bytes once per chunk it
        // cares about, not on every subsequent callback (including the
        // end-of-stream flush) -- draining the `Option` models that.
        if let Some(add) = self.add_encoded_in_data.take() {
            cb.add_encoded_data(add, false);
        }
        if let Some(f) = self.rewrite {
            f(data);
        }
        if self.release_on_end_stream && end_stream {
            return FilterDataStatus::Continue;
        }
        self.encode_data_status
    }

    fn encode_trailers(
        &mut self,
        _cb: &mut dyn EncoderCallbacks,
        _trailers: &mut ResponseTrailers,
    ) -> FilterTrailersStatus {
        self.record("encode_trailers");
        FilterTrailersStatus::Continue
    }

    fn on_destroy(&mut self) {
        self.record("on_destroy");
    }
}

/// Whether a logged `encode_data` entry (`"name:encode_data:payload:end=..."`)
/// carries a non-empty payload -- i.e. is a real frame, not the
/// end-of-stream flush's empty-data callback.
fn is_real_data_call(entry: &str) -> bool {
    match entry.splitn(4, ':').collect::<Vec<_>>().as_slice() {
        [_, "encode_data", payload, _] => !payload.is_empty(),
        _ => false,
    }
}

/// Only "real" (non-empty) `encode_data` calls for filter `name`, in log order.
fn content_calls<'a>(entries: &'a [String], name: &str) -> Vec<&'a str> {
    let prefix = format!("{name}:encode_data:");
    entries
        .iter()
        .filter(|e| e.starts_with(&prefix) && is_real_data_call(e))
        .map(|s| s.as_str())
        .collect()
}

fn request(body: &'static [u8]) -> HttpRequestParts {
    HttpRequestParts {
        head: RequestHeaders {
            method: Method::POST,
            uri: Uri::from_static("http://example.test/v1/chat"),
            headers: HeaderMap::new(),
        },
        body: bytes_to_seam_body(Bytes::from_static(body), None),
    }
}

/// Build a streaming response body out of several data frames plus an
/// optional trailers frame — the encode-side analogue of `bytes_to_seam_body`,
/// which only ever emits a single frame.
fn multi_frame_body(chunks: &[&'static [u8]], trailers: Option<HeaderMap>) -> SeamBody {
    let mut frames: Vec<Result<Frame<Bytes>, BodyError>> = chunks
        .iter()
        .map(|c| Ok(Frame::data(Bytes::from_static(c))))
        .collect();
    if let Some(t) = trailers {
        frames.push(Ok(Frame::trailers(t)));
    }
    local_boxed(StreamBody::new(futures::stream::iter(frames)))
}

/// A terminal handler that returns a fixed, pre-built response body exactly
/// once (moved out of the `RefCell` on first — and only — call).
struct FixedBodyTerminal {
    log: Log,
    body: RefCell<Option<SeamBody>>,
}

impl StreamHandler for FixedBodyTerminal {
    fn handle<'a>(
        &'a self,
        req: HttpRequestParts,
    ) -> Pin<Box<dyn Future<Output = HttpResponseParts> + 'a>> {
        Box::pin(async move {
            self.log.borrow_mut().push("terminal".to_string());
            let _ = req.body.collect().await;
            let body = self
                .body
                .borrow_mut()
                .take()
                .expect("test terminal handled more than once");
            HttpResponseParts {
                head: ResponseHeaders {
                    status: StatusCode::OK,
                    headers: HeaderMap::new(),
                },
                body,
            }
        })
    }
}

/// Run `filters` over a request, with the terminal responding with `body`.
/// Returns the (unconsumed) response so tests can drive its `StreamBody`
/// however each scenario needs (manual `poll_frame`, or `collect()`).
async fn run_streaming(
    filters: Vec<Box<dyn HttpFilter>>,
    body: SeamBody,
    buffer_limit: usize,
) -> HttpResponseParts {
    let terminal = FixedBodyTerminal {
        log: log_of(),
        body: RefCell::new(Some(body)),
    };
    let mgr = FilterManager {
        filters,
        ctx: ChainCtx::new(),
        terminal: &terminal,
        buffer_limit,
    };
    mgr.run(request(b"req")).await
}

fn block_on<F: Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(f)
}

/// A body that yields exactly one data frame and then, forever after, `Pending`
/// — never actually completing. Standing in for "the upstream response hasn't
/// finished yet".
struct OneFrameThenPending {
    frame: Option<Bytes>,
}

impl Body for OneFrameThenPending {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        // Rust note: `Option<Bytes>` is `Unpin`, so `self.get_mut()` is sound
        // without pin-projection, same reasoning as `StreamingEncoder` itself.
        let this = self.get_mut();
        match this.frame.take() {
            Some(b) => Poll::Ready(Some(Ok(Frame::data(b)))),
            None => Poll::Pending,
        }
    }
}

/// The acceptance criterion for the whole chunk: a frame the encoder chain
/// lets through reaches the caller of `poll_frame` while the upstream
/// response is still open. A buffered implementation (which must fully
/// collect the upstream response before encoding anything) could never pass
/// this: `OneFrameThenPending` never completes, so `run()` would hang
/// forever trying to collect it.
#[test]
fn response_frames_flush_before_upstream_completes() {
    block_on(async {
        let upstream = local_boxed(OneFrameThenPending {
            frame: Some(Bytes::from_static(b"chunk1")),
        });
        // No filters: proves the property is about the driver, not about
        // filter behavior masking a buffering implementation.
        let resp = run_streaming(vec![], upstream, DEFAULT_BUFFER_LIMIT).await;

        let mut body = resp.body;
        let waker = futures::task::noop_waker_ref();
        let mut cx = Context::from_waker(waker);

        let first = body.as_mut().poll_frame(&mut cx);
        let bytes = match first {
            Poll::Ready(Some(Ok(frame))) => frame.into_data().expect("data frame"),
            other => panic!("expected the first frame immediately, got {other:?}"),
        };
        assert_eq!(bytes, Bytes::from_static(b"chunk1"));

        // The upstream body never signals completion (`OneFrameThenPending`
        // returns `Pending` forever after its one frame) -- so if the driver
        // had buffered the whole response first, we'd never have gotten here.
        // The second poll must be `Pending`, not `Ready(None)`: the stream
        // genuinely isn't over.
        let second = body.as_mut().poll_frame(&mut cx);
        assert!(
            matches!(second, Poll::Pending),
            "upstream is still open; got {second:?}"
        );
    });
}

/// S2.1: each filter's `encode_data` fires exactly once per real frame, in
/// REVERSE config order, for every frame in the stream.
#[test]
fn each_filter_sees_every_frame_once_in_reverse_config_order() {
    block_on(async {
        let log = log_of();
        let filters: Vec<Box<dyn HttpFilter>> = vec![
            Box::new(ProbeFilter::new("a", log.clone())),
            Box::new(ProbeFilter::new("b", log.clone())),
            Box::new(ProbeFilter::new("c", log.clone())),
        ];
        let body = multi_frame_body(&[b"1", b"2", b"3"], None);
        let resp = run_streaming(filters, body, DEFAULT_BUFFER_LIMIT).await;
        let out = resp.body.collect().await.expect("body").to_bytes();
        assert_eq!(out, Bytes::from_static(b"123"));

        let entries = log.borrow().clone();
        let real: Vec<&str> = entries
            .iter()
            .filter(|e| e.contains(":encode_data:") && is_real_data_call(e))
            .map(|s| s.as_str())
            .collect();
        assert_eq!(
            real,
            vec![
                "c:encode_data:1:end=false",
                "b:encode_data:1:end=false",
                "a:encode_data:1:end=false",
                "c:encode_data:2:end=false",
                "b:encode_data:2:end=false",
                "a:encode_data:2:end=false",
                "c:encode_data:3:end=false",
                "b:encode_data:3:end=false",
                "a:encode_data:3:end=false",
            ],
            "each filter sees each frame once, reverse config order (S2.1); log: {entries:?}"
        );
    });
}

/// A filter can rewrite frame bytes in place; downstream (and ultimately the
/// caller) sees the rewritten content, not the original.
#[test]
fn a_filter_can_rewrite_frame_bytes_and_downstream_sees_the_rewrite() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.rewrite = Some(|data: &mut Bytes| {
            *data = Bytes::from(String::from_utf8_lossy(data).to_uppercase());
        });
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(a)];
        let body = multi_frame_body(&[b"hello"], None);
        let resp = run_streaming(filters, body, DEFAULT_BUFFER_LIMIT).await;
        let out = resp.body.collect().await.expect("body").to_bytes();
        assert_eq!(out, Bytes::from_static(b"HELLO"));
    });
}

/// A filter that holds frames (`StopIterationAndBuffer`) and only releases on
/// end-of-stream delivers its accumulated content to later positions as ONE
/// merged frame, not one call per originally-buffered chunk.
#[test]
fn buffering_filter_holds_frames_then_releases_on_end_stream() {
    block_on(async {
        let log = log_of();
        let mut holder = ProbeFilter::new("holder", log.clone());
        holder.encode_data_status = FilterDataStatus::StopIterationAndBuffer;
        holder.release_on_end_stream = true;
        let downstream = ProbeFilter::new("downstream", log.clone());
        // Config order: downstream first, holder second -- so in REVERSE
        // config (encode) order, holder is visited first (position 0,
        // closest to the router) and downstream second (position 1, closer
        // to the client) -- exactly "later positions" relative to holder.
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(downstream), Box::new(holder)];
        let body = multi_frame_body(&[b"a", b"b", b"c"], None);
        let resp = run_streaming(filters, body, DEFAULT_BUFFER_LIMIT).await;
        let out = resp.body.collect().await.expect("body").to_bytes();
        assert_eq!(
            out,
            Bytes::from_static(b"abc"),
            "the merged, released content reaches the caller"
        );

        let entries = log.borrow().clone();
        let downstream_calls: Vec<&str> = content_calls(&entries, "downstream");
        assert_eq!(
            downstream_calls,
            vec!["downstream:encode_data:abc:end=true"],
            "the filter after the holder sees the whole buffered body in ONE frame, \
             not one call per originally-buffered chunk; log: {entries:?}"
        );
    });
}

/// S2.3 (G10): the ENCODE-direction mirror of G8 (tests.rs) —
/// `StopIterationAndBuffer` on `encode_data` buffers a response-body chunk;
/// it stays buffered until release, then reaches an earlier-config-order
/// ("downstream", per this file's convention) filter and the client intact.
#[test]
fn encode_stop_iteration_and_buffer_releases_to_earlier_config_filter_and_client() {
    block_on(async {
        let log = log_of();
        let mut holder = ProbeFilter::new("holder", log.clone());
        holder.encode_data_status = FilterDataStatus::StopIterationAndBuffer;
        holder.release_on_end_stream = true;
        let downstream = ProbeFilter::new("downstream", log.clone());
        // Config order: downstream, holder -- holder is visited FIRST in
        // encode (reverse) order; downstream is earlier config order, i.e.
        // the position this case's release must reach.
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(downstream), Box::new(holder)];
        let body = multi_frame_body(&[b"resp"], None);
        let resp = run_streaming(filters, body, DEFAULT_BUFFER_LIMIT).await;
        let out = resp.body.collect().await.expect("body").to_bytes();
        assert_eq!(
            out,
            Bytes::from_static(b"resp"),
            "the buffered chunk reaches the client intact once released (S2.3)"
        );

        let entries = log.borrow().clone();
        assert!(
            content_calls(&entries, "downstream")
                .iter()
                .any(|c| c.contains("resp")),
            "the buffered chunk must reach the earlier-config filter once \
             released; log: {entries:?}"
        );
    });
}

/// S2.3 (G9's encode-direction companion): the DECODE-side
/// `StopIterationNoBuffer` "drop, don't accumulate" contract (G9, tests.rs)
/// turned out not to be implemented at all (see the task report) — but the
/// ENCODE side's `StreamingEncoder` genuinely does implement it
/// (filter_manager.rs ~L1008/L892: `pos.buf.0.clear()` when a position enters
/// `StopKind::NoBuffer`). This pins THAT: a filter returning
/// `StopIterationNoBuffer` from `encode_data` discards the chunk — including
/// anything already staged for that position via `add_encoded_data` in the
/// same call — none of it reaches the client.
#[test]
fn encode_stop_iteration_no_buffer_discards_the_chunk() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.add_encoded_in_data = Some(Bytes::from_static(b"PRE-"));
        a.encode_data_status = FilterDataStatus::StopIterationNoBuffer;
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(a)];
        let body = multi_frame_body(&[b"chunk"], None);
        let resp = run_streaming(filters, body, DEFAULT_BUFFER_LIMIT).await;
        let out = resp.body.collect().await.expect("body").to_bytes();
        assert_eq!(
            out,
            Bytes::new(),
            "StopIterationNoBuffer discards the chunk (and anything \
             add_encoded_data'd alongside it in the same call), rather than \
             accumulating it (S2.3)"
        );
    });
}

/// S2.4: trailers that arrive while data is still held wait behind it —
/// they must not be delivered before the buffered data is released.
#[test]
fn trailers_are_delivered_after_buffered_data_is_released() {
    block_on(async {
        let log = log_of();
        let mut holder = ProbeFilter::new("holder", log.clone());
        holder.encode_data_status = FilterDataStatus::StopIterationAndBuffer;
        holder.release_on_end_stream = true;
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(holder)];

        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        let body = multi_frame_body(&[b"x"], Some(trailers.clone()));
        let resp = run_streaming(filters, body, DEFAULT_BUFFER_LIMIT).await;
        let collected = resp.body.collect().await.expect("body");
        let seen_trailers = collected.trailers().cloned();
        let out = collected.to_bytes();

        assert_eq!(
            out,
            Bytes::from_static(b"x"),
            "buffered data is released first"
        );
        assert_eq!(
            seen_trailers.as_ref(),
            Some(&trailers),
            "trailers still reach the caller once the hold clears (S2.4)"
        );
    });
}

/// Once headers have already gone out, a filter buffering past the encode
/// buffer limit can no longer synthesize a 500 -- the stream truncates with
/// an error instead.
#[test]
fn encode_buffer_overflow_after_headers_truncates_the_stream_with_an_error() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.encode_data_status = FilterDataStatus::StopIterationAndBuffer; // never releases
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(a)];
        let body = multi_frame_body(&[b"0123456789"], None);
        // Limit of 4 < the 10 bytes buffered.
        let resp = run_streaming(filters, body, 4).await;

        let err =
            resp.body.collect().await.expect_err(
                "buffer overflow mid-stream must surface as a body error, not a status",
            );
        match err {
            BodyError::Upstream(source) => {
                assert!(
                    source.to_string().contains('4'),
                    "the error should name the encode buffer limit; got: {source}"
                );
            }
            other => panic!("expected BodyError::Upstream, got {other:?}"),
        }
    });
}

/// S2.2 applied to encode: a filter that holds headers still gets its own
/// `encode_data` while stopped; once it continues, headers resume at the
/// NEXT filter, and no frame is lost or delivered twice.
#[test]
fn header_hold_resolved_by_a_data_callback_still_delivers_headers_to_remaining_filters() {
    block_on(async {
        let log = log_of();
        let mut holder = ProbeFilter::new("holder", log.clone());
        holder.encode_headers_status = FilterHeadersStatus::StopIteration;
        // holder's encode_data always returns Continue -- resolves the hold
        // on the very first frame it sees.
        let downstream = ProbeFilter::new("downstream", log.clone());
        // Config order: downstream, holder -- so holder (last configured) is
        // visited FIRST in encode (reverse) order, exactly the header-hold
        // setup this test needs.
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(downstream), Box::new(holder)];
        let body = multi_frame_body(&[b"hi"], None);
        let resp = run_streaming(filters, body, DEFAULT_BUFFER_LIMIT).await;
        let out = resp.body.collect().await.expect("body").to_bytes();
        assert_eq!(out, Bytes::from_static(b"hi"));

        let entries = log.borrow().clone();
        let holder_headers = entries.iter().position(|e| e == "holder:encode_headers");
        let holder_data = entries
            .iter()
            .position(|e| e.starts_with("holder:encode_data:hi"));
        let downstream_headers = entries
            .iter()
            .position(|e| e == "downstream:encode_headers");
        assert!(
            holder_headers.is_some() && holder_data.is_some() && downstream_headers.is_some(),
            "log: {entries:?}"
        );
        assert!(
            holder_headers < holder_data && holder_data < downstream_headers,
            "holder's own data resolves the hold before downstream ever sees headers (S2.2); \
             log: {entries:?}"
        );
        let holder_data_calls = content_calls(&entries, "holder");
        assert_eq!(
            holder_data_calls.len(),
            1,
            "the frame that resolved the hold must not be redelivered to holder; log: {entries:?}"
        );
        let downstream_data_calls = content_calls(&entries, "downstream");
        assert_eq!(
            downstream_data_calls,
            vec!["downstream:encode_data:hi:end=false"],
            "downstream must see the frame exactly once, after the hold resolves; log: {entries:?}"
        );
    });
}

/// S2.7: `add_encoded_data` called from inside `encode_data` reaches
/// downstream, appended after the current frame's (possibly rewritten) bytes.
#[test]
fn add_encoded_data_during_encode_data_reaches_downstream() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.add_encoded_in_data = Some(Bytes::from_static(b"X-"));
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(a)];
        let body = multi_frame_body(&[b"body"], None);
        let resp = run_streaming(filters, body, DEFAULT_BUFFER_LIMIT).await;
        let out = resp.body.collect().await.expect("body").to_bytes();
        assert_eq!(
            out,
            Bytes::from_static(b"bodyX-"),
            "add_encoded_data reaches downstream, appended after this frame's data (S2.7)"
        );
    });
}

/// An empty filter chain is a pure pass-through for a streaming response:
/// every frame (and trailers) survives unchanged, with zero filters to index.
#[test]
fn empty_filter_chain_streams_frames_through_unchanged() {
    block_on(async {
        let mut trailers = HeaderMap::new();
        trailers.insert("x-trace", HeaderValue::from_static("1"));
        let body = multi_frame_body(&[b"a", b"b"], Some(trailers.clone()));
        let resp = run_streaming(vec![], body, DEFAULT_BUFFER_LIMIT).await;
        let collected = resp.body.collect().await.expect("body");
        let seen_trailers = collected.trailers().cloned();
        assert_eq!(collected.to_bytes(), Bytes::from_static(b"ab"));
        assert_eq!(seen_trailers.as_ref(), Some(&trailers));
    });
}

/// Per-stream teardown now happens in `Drop`, not at the end of a
/// synchronous pass -- but the ordering guarantee (S2.1: reverse creation
/// order) must hold identically once the stream actually ends.
#[test]
fn on_destroy_runs_in_reverse_creation_order_when_the_stream_ends() {
    block_on(async {
        let log = log_of();
        let filters: Vec<Box<dyn HttpFilter>> = vec![
            Box::new(ProbeFilter::new("a", log.clone())),
            Box::new(ProbeFilter::new("b", log.clone())),
            Box::new(ProbeFilter::new("c", log.clone())),
        ];
        let body = multi_frame_body(&[b"x"], None);
        let resp = run_streaming(filters, body, DEFAULT_BUFFER_LIMIT).await;
        // Driving the body to completion (and letting it drop once `collect`
        // resolves) is what ends the stream.
        let _ = resp.body.collect().await.expect("body");

        let entries = log.borrow().clone();
        let destroys: Vec<&String> = entries
            .iter()
            .filter(|e| e.ends_with(":on_destroy"))
            .collect();
        assert_eq!(
            destroys,
            vec!["c:on_destroy", "b:on_destroy", "a:on_destroy"],
            "on_destroy fires in reverse creation order once the stream ends (S2.1); \
             log: {entries:?}"
        );
    });
}

// --- per-position state machine regression tests (defects 1 & 2) ----------

/// A filter that holds exactly one real frame, then releases it combined with
/// the NEXT frame that arrives (real or the end-of-stream flush) -- a clean,
/// deterministic "pairs up frames" alternator, used to put two positions into
/// a stopped state with genuinely disjoint content at the same time, without
/// the ambiguity of a `ProbeFilter` whose status is fixed for its whole
/// lifetime.
struct PairHolder {
    name: &'static str,
    log: Log,
    held: bool,
}

impl HttpFilter for PairHolder {
    fn encode_data(
        &mut self,
        _cb: &mut dyn EncoderCallbacks,
        data: &mut Bytes,
        end_stream: bool,
    ) -> FilterDataStatus {
        self.log.borrow_mut().push(format!(
            "{}:encode_data:{}:end={end_stream}",
            self.name,
            String::from_utf8_lossy(data)
        ));
        if end_stream || self.held {
            self.held = false;
            FilterDataStatus::Continue
        } else {
            self.held = true;
            FilterDataStatus::StopIterationAndBuffer
        }
    }
}

/// **Defect 1 regression, and the most important test in this file.** A
/// counting filter sits at an EARLY position; a buffering filter sits at a
/// LATER position and holds data indefinitely (until end-of-stream). Every
/// frame must still reach the counting filter -- the bug was that once ANY
/// position was recorded as "the" stopped position, every later frame
/// resumed AT that position, silently skipping every filter before it.
///
/// This test was verified to fail against the pre-fix code (see the task
/// report): with `start_pos = self.stopped_at.unwrap_or(0)`, once the
/// buffering filter (the later position) stopped on the first frame, frames
/// 2 and 3 resumed at ITS position, so the counting filter (the earlier
/// position) never saw them -- only "1", never "2" or "3".
#[test]
fn every_filter_observes_every_frame_even_when_a_later_filter_buffers() {
    block_on(async {
        let log = log_of();
        let mut buffering = ProbeFilter::new("buffering", log.clone());
        buffering.encode_data_status = FilterDataStatus::StopIterationAndBuffer;
        buffering.release_on_end_stream = true;
        let counting = ProbeFilter::new("counting", log.clone());
        // Config order: buffering first, counting second -- so in REVERSE
        // (encode) order, counting is position 0 (visited first, "early")
        // and buffering is position 1 (visited second, "later").
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(buffering), Box::new(counting)];
        let body = multi_frame_body(&[b"1", b"2", b"3"], None);
        let resp = run_streaming(filters, body, DEFAULT_BUFFER_LIMIT).await;
        let out = resp.body.collect().await.expect("body").to_bytes();
        assert_eq!(
            out,
            Bytes::from_static(b"123"),
            "the buffered content still reaches the caller once released"
        );

        let entries = log.borrow().clone();
        let counting_calls = content_calls(&entries, "counting");
        assert_eq!(
            counting_calls,
            vec![
                "counting:encode_data:1:end=false",
                "counting:encode_data:2:end=false",
                "counting:encode_data:3:end=false",
            ],
            "the EARLY position must see every frame, regardless of what a LATER \
             position does with it; log: {entries:?}"
        );
    });
}

/// **Defect 2 regression.** Two positions become stopped at once, holding
/// DIFFERENT bytes -- position 0 grabs frame "3" while position 1 is still
/// sitting on the earlier-released "12". Releasing them must not conflate
/// whose bytes are whose: the final stream must equal the input concatenated
/// in order, and no filter's call log shows the same payload delivered twice.
#[test]
fn two_positions_stopped_at_once_release_in_stream_order_without_double_delivery() {
    block_on(async {
        let log = log_of();
        // Config order: p1 first, p0 second -- so p0 (last configured) is
        // position 0 (visited first in encode/reverse order) and p1 is
        // position 1 (visited second).
        let p1 = PairHolder {
            name: "p1",
            log: log.clone(),
            held: false,
        };
        let p0 = PairHolder {
            name: "p0",
            log: log.clone(),
            held: false,
        };
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(p1), Box::new(p0)];
        let body = multi_frame_body(&[b"1", b"2", b"3", b"4"], None);
        let resp = run_streaming(filters, body, DEFAULT_BUFFER_LIMIT).await;
        let out = resp.body.collect().await.expect("body").to_bytes();
        assert_eq!(
            out,
            Bytes::from_static(b"1234"),
            "the final stream is exactly the input, in order, however many \
             positions were stopped along the way"
        );

        let entries = log.borrow().clone();
        for name in ["p0", "p1"] {
            let calls = content_calls(&entries, name);
            let unique: std::collections::HashSet<&str> = calls.iter().copied().collect();
            assert_eq!(
                unique.len(),
                calls.len(),
                "{name} must never be handed the exact same payload twice; log: {entries:?}"
            );
        }
    });
}

/// The Envoy `Buffer` filter idiom, verbatim: `if (end_stream) return
/// Continue; return StopIterationAndBuffer;`. A buffering position must be
/// RE-INVOKED with the whole accumulated buffer on every subsequent frame --
/// not just handed each new chunk in isolation -- otherwise it could never
/// notice `end_stream` and release. Every byte must come out exactly once,
/// in order, and the filter is called once per frame (including the
/// end-of-stream flush).
#[test]
fn a_buffering_filter_is_reinvoked_with_the_accumulated_buffer() {
    block_on(async {
        let log = log_of();
        let mut holder = ProbeFilter::new("holder", log.clone());
        holder.encode_data_status = FilterDataStatus::StopIterationAndBuffer;
        holder.release_on_end_stream = true;
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(holder)];
        let body = multi_frame_body(&[b"a", b"b", b"c"], None);
        let resp = run_streaming(filters, body, DEFAULT_BUFFER_LIMIT).await;
        let out = resp.body.collect().await.expect("body").to_bytes();
        assert_eq!(out, Bytes::from_static(b"abc"));

        let entries = log.borrow().clone();
        let calls = content_calls(&entries, "holder");
        assert_eq!(
            calls,
            vec![
                "holder:encode_data:a:end=false",
                "holder:encode_data:ab:end=false",
                "holder:encode_data:abc:end=false",
                "holder:encode_data:abc:end=true",
            ],
            "each call sees the WHOLE accumulated buffer, growing with every \
             frame, until the end-of-stream call releases it; log: {entries:?}"
        );
    });
}

/// Trailers arriving while a header hold is unresolved (the filter keeps
/// returning `StopIterationAndBuffer` from its own `encode_data`, so the S2.2
/// resolution loop never sees `Continue`). Pins two things worth flagging
/// (see the task report, not fixed here -- out of scope for this change):
/// (1) the data frame the resolution loop handed to the still-held filter is
/// silently dropped if the filter doesn't ask to keep it via
/// `add_encoded_data` -- the filter manager itself does not buffer it, even
/// though `StopIterationAndBuffer` says "buffer this"; (2) trailers queued
/// this way bypass `encode_trailers` entirely (they're delivered raw), unlike
/// trailers that arrive with nothing held, which DO run through the chain.
#[test]
fn trailers_arriving_during_an_unresolved_header_hold() {
    block_on(async {
        let log = log_of();
        let mut holder = ProbeFilter::new("holder", log.clone());
        holder.encode_headers_status = FilterHeadersStatus::StopIteration;
        holder.encode_data_status = FilterDataStatus::StopIterationAndBuffer;
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(holder)];

        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        let body = multi_frame_body(&[b"x"], Some(trailers.clone()));
        let resp = run_streaming(filters, body, DEFAULT_BUFFER_LIMIT).await;
        let collected = resp.body.collect().await.expect("body");
        let seen_trailers = collected.trailers().cloned();
        let out = collected.to_bytes();

        assert_eq!(
            out,
            Bytes::new(),
            "the data handed to the still-held filter during the S2.2 \
             resolution loop is dropped, not buffered, unless the filter \
             calls add_encoded_data itself (current behavior -- see the \
             doc comment above)"
        );
        assert_eq!(
            seen_trailers.as_ref(),
            Some(&trailers),
            "trailers still reach the caller even though the hold never resolved"
        );

        let entries = log.borrow().clone();
        assert!(
            !entries.iter().any(|e| e == "holder:encode_trailers"),
            "current behavior: trailers queued behind an unresolved header \
             hold are delivered WITHOUT running through encode_trailers at \
             all (unlike trailers that arrive with nothing held); log: {entries:?}"
        );
    });
}

/// A filter that appends via `add_encoded_data` on the call that RELEASES a
/// hold: the bytes that were already buffered (from the held frame, replayed
/// ahead per S2.3) must precede the newly-added bytes, not the other way
/// around.
struct ResumeWithExtra {
    log: Log,
    calls: u32,
}

impl HttpFilter for ResumeWithExtra {
    fn encode_data(
        &mut self,
        cb: &mut dyn EncoderCallbacks,
        _data: &mut Bytes,
        _end_stream: bool,
    ) -> FilterDataStatus {
        self.calls += 1;
        self.log.borrow_mut().push(format!("calls={}", self.calls));
        match self.calls {
            1 => FilterDataStatus::StopIterationAndBuffer,
            2 => {
                cb.add_encoded_data(Bytes::from_static(b"-EXTRA"), false);
                FilterDataStatus::Continue
            }
            _ => FilterDataStatus::Continue,
        }
    }
}

/// S2.5: `send_local_reply` called after response headers have already been
/// forwarded cannot synthesize a new response (Envoy resets the stream
/// instead). We have no reset primitive through the body seam yet (TODO
/// WP-11 chunk 4), so the best available approximation is: don't silently
/// ignore the call, terminate the response body with a `BodyError`. This
/// test drives `DecoderCallbacksAdapter`/`StreamingEncoder` directly (rather
/// than through a full `run()`) because there is no reachable path in `run()`
/// today for a decoder callback to fire after encode headers have gone out —
/// decode is fully buffered and always completes first (see the module doc).
/// The scenario this guards is a decoder filter resuming late, or (once an
/// `EncoderCallbacks::send_local_reply` exists) an encoder filter calling it.
#[test]
fn local_reply_after_response_headers_forwarded_terminates_the_stream() {
    block_on(async {
        let mut ctx = ChainCtx::new();
        ctx.response_headers_forwarded = true;
        {
            let mut cb = DecoderCallbacksAdapter { ctx: &mut ctx };
            cb.send_local_reply(StatusCode::FORBIDDEN, "too late", None, "after_headers");
        }
        assert!(
            ctx.reset_after_headers,
            "must record 'reset requested', not silently drop the call"
        );
        assert!(
            ctx.local_reply.is_none(),
            "must NOT synthesize a new response once headers are already out"
        );

        let encoder = StreamingEncoder {
            filters: vec![],
            ctx,
            upstream: bytes_to_seam_body(Bytes::new(), None),
            buffer_limit: DEFAULT_BUFFER_LIMIT,
            pending: VecDeque::new(),
            pending_trailers: None,
            upstream_done: true,
            end_flush_done: false,
            flush_pos: 0,
            destroyed: false,
        };
        let mut body = local_boxed(encoder);
        let err = body
            .as_mut()
            .collect()
            .await
            .expect_err("the stream must terminate with an error, not silently succeed");
        match err {
            // The CORRECT Envoy behavior is a stream RESET, not a body error
            // -- pinned here as the current best-effort approximation until
            // WP-11 chunk 4 plumbs a real reset primitive through the seam.
            BodyError::Upstream(_) => {}
            other => panic!("expected BodyError::Upstream, got {other:?}"),
        }
    });
}

#[test]
fn add_encoded_data_ordering_survives_a_stop_and_resume() {
    block_on(async {
        let log = log_of();
        let filter = ResumeWithExtra {
            log: log.clone(),
            calls: 0,
        };
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(filter)];
        let body = multi_frame_body(&[b"A", b"B"], None);
        let resp = run_streaming(filters, body, DEFAULT_BUFFER_LIMIT).await;
        let out = resp.body.collect().await.expect("body").to_bytes();
        assert_eq!(
            out,
            Bytes::from_static(b"AB-EXTRA"),
            "bytes buffered from the held frame(s) come first (S2.3 replay), \
             the newly add_encoded_data'd bytes ride after them, not before"
        );
    });
}

/// A filter that lets exactly one call through, then holds every subsequent
/// call forever (never releases) -- used to get TWO positions stopped at
/// once with neither individually over the limit, so the sum must be what's
/// checked (defect 2's buffer-limit corollary).
struct HoldAfterFirst {
    log: Log,
    seen_first: bool,
}

impl HttpFilter for HoldAfterFirst {
    fn encode_data(
        &mut self,
        _cb: &mut dyn EncoderCallbacks,
        data: &mut Bytes,
        end_stream: bool,
    ) -> FilterDataStatus {
        self.log.borrow_mut().push(format!(
            "hold_after_first:encode_data:{}:end={end_stream}",
            String::from_utf8_lossy(data)
        ));
        if self.seen_first {
            FilterDataStatus::StopIterationAndBuffer
        } else {
            self.seen_first = true;
            FilterDataStatus::Continue
        }
    }
}

/// Neither position alone holds more than the limit, but the limit is
/// per-STREAM: the sum across both positions must be what overflow checks.
#[test]
fn encode_buffer_overflow_is_checked_as_the_sum_across_positions() {
    block_on(async {
        let log = log_of();
        // Config order: downstream (holds whatever reaches it) first, then
        // the position-0 gatekeeper -- same convention as elsewhere in this
        // file: last configured = position 0 (visited first).
        let mut downstream = ProbeFilter::new("downstream", log.clone());
        downstream.encode_data_status = FilterDataStatus::StopIterationAndBuffer; // never releases
        let gatekeeper = HoldAfterFirst {
            log: log.clone(),
            seen_first: false,
        };
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(downstream), Box::new(gatekeeper)];
        // "12345" (5 bytes) passes the gatekeeper (its first call) and is
        // held at `downstream`; "6789" (4 bytes) is held AT the gatekeeper
        // (its second call onward) and never reaches `downstream`. Neither
        // position alone (5, or 4) exceeds the limit of 8; their sum (9) does.
        let body = multi_frame_body(&[b"12345", b"6789"], None);
        let resp = run_streaming(filters, body, 8).await;

        let err =
            resp.body.collect().await.expect_err(
                "the sum across positions must be checked, not just one position's buffer",
            );
        match err {
            BodyError::Upstream(source) => {
                assert!(
                    source.to_string().contains('8'),
                    "the error should name the encode buffer limit; got: {source}"
                );
            }
            other => panic!("expected BodyError::Upstream, got {other:?}"),
        }
    });
}
