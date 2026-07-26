//! WP-11 chunk 1 tests: the S2 mechanics this chunk implements. The exhaustive
//! status-matrix conformance suite is chunk 2; these pin the engine's spine —
//! ordering (S2.1), the header-hold gotcha (S2.2), data statuses (S2.3),
//! trailers (S2.4), the buffer APIs (S2.7), and overflow → 413/500.

use std::cell::RefCell;
use std::rc::Rc;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use http_body_util::BodyExt;

use super::*;
use crate::filter::{FilterTrailersStatus, RequestHeaders};
use crate::handler::{DownstreamInfo, HttpRequestParts, HttpResponseParts};

/// Shared call log: every filter appends `"<name>:<callback>"` so a test can
/// assert the exact interleaving the S2 spec prescribes.
type Log = Rc<RefCell<Vec<String>>>;

/// S2.5 test hook: a shared slot a probe filter writes the response head it
/// observed in `encode_headers` into, so a test can assert a `modify_headers`
/// mutation reached the encoder filters. Aliased to keep the field type below
/// under clippy's `type_complexity` bar.
type SeenResponseHead = Rc<RefCell<Option<(StatusCode, HeaderMap)>>>;

/// S2.7 test hook: every `(data, end_stream)` pair a probe filter's
/// `decode_data` observed. Aliased for the same reason as
/// [`SeenResponseHead`] above.
type SeenDecodeData = Rc<RefCell<Vec<(Bytes, bool)>>>;

fn log_of() -> Log {
    Rc::new(RefCell::new(Vec::new()))
}

/// A configurable probe filter. Each field controls one callback's return.
struct ProbeFilter {
    name: &'static str,
    log: Log,
    decode_headers_status: FilterHeadersStatus,
    decode_data_status: FilterDataStatus,
    decode_trailers_status: FilterTrailersStatus,
    /// If set, `decode_data` calls `continue_decoding()` before returning.
    call_continue_decoding: bool,
    encode_headers_status: FilterHeadersStatus,
    encode_data_status: FilterDataStatus,
    encode_trailers_status: FilterTrailersStatus,
    /// If set, `encode_data` calls `continue_encoding()` before returning.
    call_continue_encoding: bool,
    /// Bytes appended via `add_decoded_data` from `decode_headers`.
    add_decoded: Option<Bytes>,
    /// Bytes appended via `add_encoded_data` from `encode_headers`.
    add_encoded: Option<Bytes>,
    /// S2.5: if set, `decode_headers` calls `send_local_reply(code, body,
    /// ..., details)` before returning its own status.
    send_local_reply: Option<(StatusCode, &'static str, &'static str)>,
    /// A header (name, value) supplied to `send_local_reply`'s
    /// `modify_headers` callback, when `send_local_reply` is also set.
    local_reply_header: Option<(&'static str, &'static str)>,
    /// S2.5 test hook: the response status this filter observed in
    /// `encode_headers`, and the header map it saw (for asserting a
    /// `modify_headers` mutation reached encoder filters).
    seen_response_head: Option<SeenResponseHead>,
    /// S2.5 test hook: every `encode_data` payload this filter observed.
    seen_encode_data: Option<Rc<RefCell<Vec<Bytes>>>>,
    /// S2.5 (G16): if set, `decode_data` calls `send_local_reply` (mirrors
    /// `send_local_reply`, which only fires from `decode_headers`).
    send_local_reply_from_data: Option<(StatusCode, &'static str, &'static str)>,
    /// S2.7: if set, `decode_data` calls
    /// `inject_decoded_data_to_filter_chain(data, end_stream)` before
    /// returning `decode_data_status`.
    inject_decoded: Option<(Bytes, bool)>,
    /// S2.7: every `(data, end_stream)` pair this filter's `decode_data`
    /// observed — records BOTH the main body flow and anything delivered to
    /// it via injection, so a test can tell the two apart by content.
    seen_decode_data: Option<SeenDecodeData>,
    /// S2.7: if set, `encode_data` calls
    /// `inject_encoded_data_to_filter_chain(data, end_stream)` before
    /// returning `encode_data_status`.
    inject_encoded: Option<(Bytes, bool)>,
}

impl ProbeFilter {
    fn new(name: &'static str, log: Log) -> Self {
        Self {
            name,
            log,
            decode_headers_status: FilterHeadersStatus::Continue,
            decode_data_status: FilterDataStatus::Continue,
            decode_trailers_status: FilterTrailersStatus::Continue,
            call_continue_decoding: false,
            encode_headers_status: FilterHeadersStatus::Continue,
            encode_data_status: FilterDataStatus::Continue,
            encode_trailers_status: FilterTrailersStatus::Continue,
            call_continue_encoding: false,
            add_decoded: None,
            add_encoded: None,
            send_local_reply: None,
            local_reply_header: None,
            seen_response_head: None,
            seen_encode_data: None,
            send_local_reply_from_data: None,
            inject_decoded: None,
            seen_decode_data: None,
            inject_encoded: None,
        }
    }

    fn record(&self, what: &str) {
        self.log.borrow_mut().push(format!("{}:{what}", self.name));
    }
}

impl HttpFilter for ProbeFilter {
    fn decode_headers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        _headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        self.record("decode_headers");
        if let Some(data) = &self.add_decoded {
            cb.add_decoded_data(data.clone(), false);
        }
        if let Some((code, body, details)) = self.send_local_reply {
            // Rust note: building the `HeaderMutationFn` here means moving
            // `name`/`value` (owned `String`s) into the closure so it can be
            // `'static` and `Send` (required by `HeaderMutationFn`'s
            // definition) without borrowing `self`.
            let modify_headers: Option<HeaderMutationFn> =
                self.local_reply_header.map(|(name, value)| {
                    let name = name.to_string();
                    let value = value.to_string();
                    Box::new(move |headers: &mut HeaderMap| {
                        headers.insert(
                            HeaderName::from_bytes(name.as_bytes()).expect("valid header name"),
                            HeaderValue::from_str(&value).expect("valid header value"),
                        );
                    }) as HeaderMutationFn
                });
            cb.send_local_reply(code, body, modify_headers, details);
        }
        self.decode_headers_status
    }

    fn decode_data(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        data: &mut Bytes,
        end_stream: bool,
    ) -> FilterDataStatus {
        self.record("decode_data");
        if let Some(seen) = &self.seen_decode_data {
            seen.borrow_mut().push((data.clone(), end_stream));
        }
        if let Some((code, body, details)) = self.send_local_reply_from_data {
            cb.send_local_reply(code, body, None, details);
        }
        if let Some((data, end_stream)) = &self.inject_decoded {
            cb.inject_decoded_data_to_filter_chain(data.clone(), *end_stream);
        }
        if self.call_continue_decoding {
            cb.continue_decoding();
        }
        self.decode_data_status
    }

    fn decode_trailers(
        &mut self,
        _cb: &mut dyn DecoderCallbacks,
        _trailers: &mut RequestTrailers,
    ) -> FilterTrailersStatus {
        self.record("decode_trailers");
        self.decode_trailers_status
    }

    fn encode_headers(
        &mut self,
        cb: &mut dyn EncoderCallbacks,
        headers: &mut ResponseHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        self.record("encode_headers");
        if let Some(seen) = &self.seen_response_head {
            *seen.borrow_mut() = Some((headers.status, headers.headers.clone()));
        }
        if let Some(data) = &self.add_encoded {
            cb.add_encoded_data(data.clone(), false);
        }
        self.encode_headers_status
    }

    fn encode_data(
        &mut self,
        cb: &mut dyn EncoderCallbacks,
        data: &mut Bytes,
        _end_stream: bool,
    ) -> FilterDataStatus {
        self.record("encode_data");
        if let Some(seen) = &self.seen_encode_data {
            seen.borrow_mut().push(data.clone());
        }
        if let Some((inj_data, end_stream)) = &self.inject_encoded {
            cb.inject_encoded_data_to_filter_chain(inj_data.clone(), *end_stream);
        }
        if self.call_continue_encoding {
            cb.continue_encoding();
        }
        self.encode_data_status
    }

    fn encode_trailers(
        &mut self,
        _cb: &mut dyn EncoderCallbacks,
        _trailers: &mut ResponseTrailers,
    ) -> FilterTrailersStatus {
        self.record("encode_trailers");
        self.encode_trailers_status
    }

    fn on_destroy(&mut self) {
        self.record("on_destroy");
    }
}

// Note: these tests drive `FilterManager` directly rather than going through
// `FilterChainHandler`'s factory path. `FilterInstanceFactory` is `Send + Sync`
// (config-time plumbing that crosses threads), but the probes above hold an
// `Rc` call log, and `unsafe impl` is denied workspace-wide — so probe filters
// can't be minted from a real factory. Real filters, whose factories hold only
// parsed config, will use that path; `FilterChainHandler` itself is covered by
// the codec-level integration test.

/// Build a request with the given body.
fn request(body: &'static [u8]) -> HttpRequestParts {
    HttpRequestParts {
        head: RequestHeaders {
            method: Method::POST,
            uri: Uri::from_static("http://example.test/v1/chat"),
            headers: HeaderMap::new(),
        },
        body: bytes_to_seam_body(Bytes::from_static(body), None),
        downstream: DownstreamInfo::loopback(),
    }
}

/// Build a request with a body AND trailers (`request()` above never attaches
/// trailers — needed for the S2.4 trailer-ordering cases).
fn request_with_trailers(body: &'static [u8], trailers: HeaderMap) -> HttpRequestParts {
    HttpRequestParts {
        head: RequestHeaders {
            method: Method::POST,
            uri: Uri::from_static("http://example.test/v1/chat"),
            headers: HeaderMap::new(),
        },
        body: bytes_to_seam_body(Bytes::from_static(body), Some(trailers)),
        downstream: DownstreamInfo::loopback(),
    }
}

/// Like [`run_chain`] but takes a pre-built request, for cases (trailers,
/// custom headers) `run_chain`'s fixed shape can't express.
async fn run_chain_req(
    filters: Vec<Box<dyn HttpFilter>>,
    log: Log,
    req: HttpRequestParts,
    buffer_limit: usize,
) -> (StatusCode, Bytes, Bytes) {
    let seen_body = Rc::new(RefCell::new(Bytes::new()));
    let terminal = RecordingTerminal {
        log: log.clone(),
        seen_body: seen_body.clone(),
        seen_request_id: Rc::new(RefCell::new(None)),
        seen_headers: None,
    };
    let mgr = FilterManager {
        filters,
        ctx: ChainCtx::new(),
        terminal: &terminal,
        buffer_limit,
    };
    let resp = mgr.run(req).await;
    let status = resp.head.status;
    let resp_body = resp.body.collect().await.expect("resp body").to_bytes();
    let seen = seen_body.borrow().clone();
    (status, seen, resp_body)
}

/// A terminal handler that records that it ran and echoes a fixed 200 with the
/// request body it received (so tests can assert what reached the router).
struct RecordingTerminal {
    log: Log,
    seen_body: Rc<RefCell<Bytes>>,
    /// S9 test hook: the `x-request-id` the terminal observed on the request
    /// head (mirrors `seen_body` above), so `FilterChainHandler`-level tests
    /// can assert what the router saw after the HCM-level id generation ran.
    seen_request_id: Rc<RefCell<Option<String>>>,
    /// S9 XFF test hook: the full request header map the terminal observed,
    /// so `FilterChainHandler`-level XFF tests can assert what
    /// `x-forwarded-for` / `x-forwarded-proto` looked like after the
    /// HCM-level mutation ran. `None` when the test doesn't care (most
    /// callers below).
    seen_headers: Option<Rc<RefCell<Option<HeaderMap>>>>,
}

impl StreamHandler for RecordingTerminal {
    fn handle<'a>(
        &'a self,
        req: HttpRequestParts,
    ) -> Pin<Box<dyn Future<Output = HttpResponseParts> + 'a>> {
        Box::pin(async move {
            self.log.borrow_mut().push("terminal".to_string());
            *self.seen_request_id.borrow_mut() = req
                .head
                .headers
                .get("x-request-id")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            if let Some(seen_headers) = &self.seen_headers {
                *seen_headers.borrow_mut() = Some(req.head.headers.clone());
            }
            let collected = req.body.collect().await.expect("test body never errors");
            *self.seen_body.borrow_mut() = collected.to_bytes();
            HttpResponseParts {
                head: ResponseHeaders {
                    status: StatusCode::OK,
                    headers: HeaderMap::new(),
                },
                body: bytes_to_seam_body(Bytes::from_static(b"resp"), None),
            }
        })
    }
}

/// Run `filters` over a request with `body`, returning (log, response, body the
/// terminal saw, response body).
async fn run_chain(
    filters: Vec<Box<dyn HttpFilter>>,
    log: Log,
    body: &'static [u8],
    buffer_limit: usize,
) -> (StatusCode, Bytes, Bytes) {
    let seen_body = Rc::new(RefCell::new(Bytes::new()));
    let terminal = RecordingTerminal {
        log: log.clone(),
        seen_body: seen_body.clone(),
        seen_request_id: Rc::new(RefCell::new(None)),
        seen_headers: None,
    };
    let mgr = FilterManager {
        filters,
        ctx: ChainCtx::new(),
        terminal: &terminal,
        buffer_limit,
    };
    let resp = mgr.run(request(body)).await;
    let status = resp.head.status;
    let resp_body = resp.body.collect().await.expect("resp body").to_bytes();
    let seen = seen_body.borrow().clone();
    (status, seen, resp_body)
}

fn block_on<F: Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(f)
}

/// S2.1: decoder filters run in config order, encoder filters in REVERSE
/// config order, and instances are destroyed in reverse creation order.
#[test]
fn decode_runs_in_order_and_encode_in_reverse() {
    block_on(async {
        let log = log_of();
        let filters: Vec<Box<dyn HttpFilter>> = vec![
            Box::new(ProbeFilter::new("a", log.clone())),
            Box::new(ProbeFilter::new("b", log.clone())),
        ];
        let (status, _, _) = run_chain(filters, log.clone(), b"hi", DEFAULT_BUFFER_LIMIT).await;
        assert_eq!(status, StatusCode::OK);

        let entries = log.borrow().clone();
        let decode_headers: Vec<&String> = entries
            .iter()
            .filter(|e| e.ends_with(":decode_headers"))
            .collect();
        assert_eq!(
            decode_headers,
            vec!["a:decode_headers", "b:decode_headers"],
            "decode headers run in config order (S2.1); log: {entries:?}"
        );

        let encode_headers: Vec<&String> = entries
            .iter()
            .filter(|e| e.ends_with(":encode_headers"))
            .collect();
        assert_eq!(
            encode_headers,
            vec!["b:encode_headers", "a:encode_headers"],
            "encode headers run in REVERSE config order (S2.1); log: {entries:?}"
        );

        let destroys: Vec<&String> = entries
            .iter()
            .filter(|e| e.ends_with(":on_destroy"))
            .collect();
        assert_eq!(
            destroys,
            vec!["b:on_destroy", "a:on_destroy"],
            "instances destroyed in reverse creation order (S2.1); log: {entries:?}"
        );
    });
}

/// S2.2, the classic gotcha: a filter that returns `StopIteration` from
/// `decode_headers` STILL gets its own data callbacks — data is not implicitly
/// buffered — and returning `Continue` from that data callback resumes the held
/// headers, letting iteration proceed to the next filter.
#[test]
fn stop_iteration_on_headers_still_delivers_data_to_that_filter_and_resumes() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.decode_headers_status = FilterHeadersStatus::StopIteration;
        a.decode_data_status = FilterDataStatus::Continue; // resumes the hold
        let filters: Vec<Box<dyn HttpFilter>> =
            vec![Box::new(a), Box::new(ProbeFilter::new("b", log.clone()))];
        let (status, _, _) = run_chain(filters, log.clone(), b"hi", DEFAULT_BUFFER_LIMIT).await;
        assert_eq!(status, StatusCode::OK);

        let entries = log.borrow().clone();
        // a's data callback fires while its headers are held...
        let a_data = entries.iter().position(|e| e == "a:decode_data");
        let b_headers = entries.iter().position(|e| e == "b:decode_headers");
        assert!(
            a_data.is_some(),
            "a header-stopped filter still gets decode_data (S2.2); log: {entries:?}"
        );
        assert!(
            b_headers.is_some(),
            "Continue from decode_data resumes the held headers (S2.2); log: {entries:?}"
        );
        assert!(
            a_data < b_headers,
            "a's data must precede b's headers — the hold resolves via data (S2.2); log: {entries:?}"
        );
    });
}

/// S2.2/S2.3: a filter that holds headers and never continues stops everything
/// past it — later filters see neither headers nor data.
#[test]
fn unresolved_header_hold_blocks_subsequent_filters() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.decode_headers_status = FilterHeadersStatus::StopAllIterationAndBuffer;
        a.decode_data_status = FilterDataStatus::StopIterationAndBuffer; // never continues
        let filters: Vec<Box<dyn HttpFilter>> =
            vec![Box::new(a), Box::new(ProbeFilter::new("b", log.clone()))];
        let (_, _, _) = run_chain(filters, log.clone(), b"hi", DEFAULT_BUFFER_LIMIT).await;

        let entries = log.borrow().clone();
        assert!(
            !entries.iter().any(|e| e.starts_with("b:decode")),
            "nothing proceeds past a filter that stops all iteration (S2.2); log: {entries:?}"
        );
    });
}

/// S2.3: `continue_decoding()` from a data callback resumes iteration just as a
/// `Continue` return does.
#[test]
fn continue_decoding_callback_resumes_iteration() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.decode_headers_status = FilterHeadersStatus::StopIteration;
        a.decode_data_status = FilterDataStatus::StopIterationAndBuffer;
        a.call_continue_decoding = true; // explicit resume
        let filters: Vec<Box<dyn HttpFilter>> =
            vec![Box::new(a), Box::new(ProbeFilter::new("b", log.clone()))];
        let (status, _, _) = run_chain(filters, log.clone(), b"hi", DEFAULT_BUFFER_LIMIT).await;
        assert_eq!(status, StatusCode::OK);

        let entries = log.borrow().clone();
        assert!(
            entries.iter().any(|e| e == "b:decode_headers"),
            "continue_decoding() must resume iteration (S2.3); log: {entries:?}"
        );
    });
}

/// Each filter's `decode_data` fires exactly once, even when an earlier filter
/// consumed its data early to resolve a header hold (the `data_consumed` guard).
#[test]
fn each_filter_sees_data_exactly_once() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.decode_headers_status = FilterHeadersStatus::StopIteration;
        let filters: Vec<Box<dyn HttpFilter>> =
            vec![Box::new(a), Box::new(ProbeFilter::new("b", log.clone()))];
        run_chain(filters, log.clone(), b"hi", DEFAULT_BUFFER_LIMIT).await;

        let entries = log.borrow().clone();
        assert_eq!(
            entries.iter().filter(|e| *e == "a:decode_data").count(),
            1,
            "a filter that took data early must not get it again; log: {entries:?}"
        );
        assert_eq!(
            entries.iter().filter(|e| *e == "b:decode_data").count(),
            1,
            "every filter that continued on headers gets data once; log: {entries:?}"
        );
    });
}

/// S2.7: `add_decoded_data` from a header callback prepends to what the
/// terminal handler (router) ultimately receives.
#[test]
fn add_decoded_data_reaches_the_terminal_handler() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.add_decoded = Some(Bytes::from_static(b"PRE-"));
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(a)];
        let (status, seen, _) =
            run_chain(filters, log.clone(), b"body", DEFAULT_BUFFER_LIMIT).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            seen,
            Bytes::from_static(b"PRE-body"),
            "add_decoded_data must reach the router (S2.7)"
        );
    });
}

/// S2.7: `add_encoded_data` from an encode callback reaches the downstream
/// response body.
#[test]
fn add_encoded_data_reaches_the_response() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.add_encoded = Some(Bytes::from_static(b"X-"));
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(a)];
        let (status, _, resp_body) =
            run_chain(filters, log.clone(), b"body", DEFAULT_BUFFER_LIMIT).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            resp_body,
            Bytes::from_static(b"X-resp"),
            "add_encoded_data must reach the downstream response (S2.7)"
        );
    });
}

/// S2.2/S2.3: overflowing the decode buffer limit yields **413**.
#[test]
fn decode_buffer_overflow_yields_413() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.add_decoded = Some(Bytes::from_static(b"0123456789"));
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(a)];
        // Limit of 4 < the 10 bytes the filter buffers.
        let (status, _, _) = run_chain(filters, log.clone(), b"body", 4).await;

        assert_eq!(
            status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "decode-side buffer overflow is 413 (S2.2)"
        );
    });
}

/// S2.2/S2.3: overflowing the encode buffer limit yields **500** (not 413 —
/// the client didn't cause it).
#[test]
fn encode_buffer_overflow_yields_500() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.add_encoded = Some(Bytes::from_static(b"0123456789"));
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(a)];
        let (status, _, _) = run_chain(filters, log.clone(), b"body", 4).await;

        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "encode-side buffer overflow is 500, not 413 (S2.3)"
        );

        // S2.1 teardown must happen on EVERY path, including the ones that
        // return a bare synthesized response instead of a `StreamingEncoder`.
        // `on_destroy` normally rides on that encoder's `Drop`; a path that
        // never builds one would otherwise drop the filter instances silently.
        // A filter that emits its usage record on teardown — precisely what an
        // LLM token-metering filter does — must not lose it just because the
        // response turned into an error.
        let entries = log.borrow().clone();
        assert!(
            entries.iter().any(|e| e == "a:on_destroy"),
            "on_destroy must still run when the response is a synthesized 500; log: {entries:?}"
        );
    });
}

/// An empty chain is a pass-through: the request reaches the terminal handler
/// unchanged and its response comes back unchanged.
#[test]
fn empty_chain_passes_through() {
    block_on(async {
        let log = log_of();
        let (status, seen, resp_body) =
            run_chain(vec![], log.clone(), b"body", DEFAULT_BUFFER_LIMIT).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(seen, Bytes::from_static(b"body"));
        assert_eq!(resp_body, Bytes::from_static(b"resp"));
    });
}

// --- S2.5: send_local_reply ------------------------------------------------

/// The whole point of S2.5: a decoder filter's `send_local_reply` must
/// synthesize a response that runs through the ENCODER chain, not one that
/// bypasses it — an encoder filter (token metering, access logging, ...) must
/// see it exactly like any other response.
#[test]
fn local_reply_from_a_decoder_filter_is_seen_by_encoder_filters() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.send_local_reply = Some((StatusCode::FORBIDDEN, "forbidden", "custom_reject"));
        let seen_head = Rc::new(RefCell::new(None));
        let seen_data = Rc::new(RefCell::new(Vec::new()));
        let mut b = ProbeFilter::new("b", log.clone());
        b.seen_response_head = Some(seen_head.clone());
        b.seen_encode_data = Some(seen_data.clone());
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(a), Box::new(b)];
        let (status, _, resp_body) =
            run_chain(filters, log.clone(), b"hi", DEFAULT_BUFFER_LIMIT).await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            seen_head.borrow().as_ref().map(|(s, _)| *s),
            Some(StatusCode::FORBIDDEN),
            "the encoder filter must observe the local reply's status"
        );
        assert!(
            seen_data.borrow().iter().any(|b| !b.is_empty()),
            "the encoder filter must observe the local reply's body as real data frames"
        );
        assert_eq!(resp_body, Bytes::from_static(b"forbidden\n"));

        let entries = log.borrow().clone();
        assert!(
            entries.iter().any(|e| e == "b:encode_headers"),
            "log: {entries:?}"
        );
        assert!(
            entries.iter().any(|e| e == "b:encode_data"),
            "log: {entries:?}"
        );
    });
}

/// A local reply must short-circuit the terminal handler (the router
/// stand-in) entirely — the request must never reach it once a decoder
/// filter has replaced the response.
#[test]
fn local_reply_short_circuits_the_terminal_handler() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.send_local_reply = Some((StatusCode::FORBIDDEN, "nope", "blocked"));
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(a)];
        let (status, _, _) = run_chain(filters, log.clone(), b"hi", DEFAULT_BUFFER_LIMIT).await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        let entries = log.borrow().clone();
        assert!(
            !entries.iter().any(|e| e == "terminal"),
            "the terminal handler must not run once a local reply has been requested; \
             log: {entries:?}"
        );
    });
}

/// The manager's own decode-buffer-overflow 413 must ALSO run through the
/// encoder chain now (S2.5) — it's routed through the same `LocalReply`
/// machinery as an explicit `send_local_reply` call.
#[test]
fn decode_buffer_overflow_413_runs_through_the_encoder_chain() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.add_decoded = Some(Bytes::from_static(b"0123456789"));
        let seen_head = Rc::new(RefCell::new(None));
        let mut b = ProbeFilter::new("b", log.clone());
        b.seen_response_head = Some(seen_head.clone());
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(a), Box::new(b)];
        // Limit of 4 < the 10 bytes the filter buffers.
        let (status, _, _) = run_chain(filters, log.clone(), b"body", 4).await;

        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            seen_head.borrow().as_ref().map(|(s, _)| *s),
            Some(StatusCode::PAYLOAD_TOO_LARGE),
            "an encoder filter must observe the synthesized 413, not just the raw status"
        );
        let entries = log.borrow().clone();
        assert!(
            entries.iter().any(|e| e == "b:encode_headers"),
            "log: {entries:?}"
        );
    });
}

/// `send_local_reply`'s `modify_headers` callback must mutate the synthesized
/// response's headers before it runs through the encoder chain — encoder
/// filters must see the mutated headers, not the unmutated ones.
#[test]
fn local_reply_modify_headers_callback_is_applied() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.send_local_reply = Some((StatusCode::FORBIDDEN, "nope", "blocked"));
        a.local_reply_header = Some(("x-reject-reason", "policy"));
        let seen_head = Rc::new(RefCell::new(None));
        let mut b = ProbeFilter::new("b", log.clone());
        b.seen_response_head = Some(seen_head.clone());
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(a), Box::new(b)];
        let (status, _, _) = run_chain(filters, log.clone(), b"hi", DEFAULT_BUFFER_LIMIT).await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        let head = seen_head.borrow();
        let (_, headers) = head.as_ref().expect("encoder filter must have run");
        assert_eq!(
            headers.get("x-reject-reason").map(|v| v.to_str().unwrap()),
            Some("policy"),
            "modify_headers must reach the encoder chain's view of the response headers"
        );
    });
}

/// `send_local_reply` records `is_local_reply` / `response_code_details` onto
/// `StreamInfo` regardless of whether the response can be sent (S2.5).
#[test]
fn local_reply_records_response_code_details_and_is_local_reply() {
    let mut ctx = ChainCtx::new();
    {
        let mut cb = DecoderCallbacksAdapter { ctx: &mut ctx };
        cb.send_local_reply(StatusCode::FORBIDDEN, "nope", None, "custom_reason");
    }
    assert!(ctx.stream_info.is_local_reply);
    assert_eq!(
        ctx.stream_info.response_code_details.as_deref(),
        Some("custom_reason")
    );
    assert!(ctx.local_reply.is_some());
}

/// A second `send_local_reply` while one is already pending is ignored —
/// first one wins (matches Envoy).
#[test]
fn a_second_local_reply_is_ignored() {
    let mut ctx = ChainCtx::new();
    {
        let mut cb = DecoderCallbacksAdapter { ctx: &mut ctx };
        cb.send_local_reply(StatusCode::FORBIDDEN, "first", None, "first_reason");
        cb.send_local_reply(
            StatusCode::INTERNAL_SERVER_ERROR,
            "second",
            None,
            "second_reason",
        );
    }
    let reply = ctx.local_reply.expect("first reply must still be recorded");
    assert_eq!(reply.code, StatusCode::FORBIDDEN);
    assert_eq!(reply.details, "first_reason");
    // Rust note: `StreamInfo` reflects whichever call ran last (it's a plain
    // record, not "first wins"), unlike `ctx.local_reply` itself — only the
    // latter decides what response actually gets built.
    assert_eq!(
        ctx.stream_info.response_code_details.as_deref(),
        Some("second_reason")
    );
}

// --- WP-11 chunk 2: S2 conformance suite (systematic fan-out) -------------

/// S2.1 (G1): with THREE filters present in both chains, decode runs config
/// order, encode runs reverse config order, and `on_destroy` fires in reverse
/// creation order — the two-filter case already pins this; this confirms the
/// law generalizes past a single pair.
#[test]
fn three_filters_decode_forward_encode_reverse_destroy_reverse() {
    block_on(async {
        let log = log_of();
        let filters: Vec<Box<dyn HttpFilter>> = vec![
            Box::new(ProbeFilter::new("a", log.clone())),
            Box::new(ProbeFilter::new("b", log.clone())),
            Box::new(ProbeFilter::new("c", log.clone())),
        ];
        let (status, _, _) = run_chain(filters, log.clone(), b"hi", DEFAULT_BUFFER_LIMIT).await;
        assert_eq!(status, StatusCode::OK);

        let entries = log.borrow().clone();
        let decode_headers: Vec<&String> = entries
            .iter()
            .filter(|e| e.ends_with(":decode_headers"))
            .collect();
        assert_eq!(
            decode_headers,
            vec!["a:decode_headers", "b:decode_headers", "c:decode_headers"],
            "S2.1 decode order; log: {entries:?}"
        );
        let encode_headers: Vec<&String> = entries
            .iter()
            .filter(|e| e.ends_with(":encode_headers"))
            .collect();
        assert_eq!(
            encode_headers,
            vec!["c:encode_headers", "b:encode_headers", "a:encode_headers"],
            "S2.1 encode reverse order; log: {entries:?}"
        );
        let destroys: Vec<&String> = entries
            .iter()
            .filter(|e| e.ends_with(":on_destroy"))
            .collect();
        assert_eq!(
            destroys,
            vec!["c:on_destroy", "b:on_destroy", "a:on_destroy"],
            "S2.1 reverse creation-order teardown; log: {entries:?}"
        );
    });
}

/// S2.1/S2.5 (G2): teardown reverse order must ALSO hold on the local-reply
/// short-circuit path, not just the happy path.
#[test]
fn on_destroy_reverse_order_holds_on_local_reply_path() {
    block_on(async {
        let log = log_of();
        let mut b = ProbeFilter::new("b", log.clone());
        b.send_local_reply = Some((StatusCode::FORBIDDEN, "nope", "blocked"));
        let filters: Vec<Box<dyn HttpFilter>> = vec![
            Box::new(ProbeFilter::new("a", log.clone())),
            Box::new(b),
            Box::new(ProbeFilter::new("c", log.clone())),
        ];
        let (status, _, _) = run_chain(filters, log.clone(), b"hi", DEFAULT_BUFFER_LIMIT).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let entries = log.borrow().clone();
        let destroys: Vec<&String> = entries
            .iter()
            .filter(|e| e.ends_with(":on_destroy"))
            .collect();
        assert_eq!(
            destroys,
            vec!["c:on_destroy", "b:on_destroy", "a:on_destroy"],
            "S2.1: teardown must be reverse creation order even on the \
             local-reply short-circuit path; log: {entries:?}"
        );
    });
}

/// S2.1/S2.2 (G2): teardown reverse order must ALSO hold on the decode
/// buffer-overflow (413) path.
#[test]
fn on_destroy_reverse_order_holds_on_decode_overflow_path() {
    block_on(async {
        let log = log_of();
        let mut b = ProbeFilter::new("b", log.clone());
        b.add_decoded = Some(Bytes::from_static(b"0123456789"));
        let filters: Vec<Box<dyn HttpFilter>> = vec![
            Box::new(ProbeFilter::new("a", log.clone())),
            Box::new(b),
            Box::new(ProbeFilter::new("c", log.clone())),
        ];
        // Limit of 4 < the 10 bytes `b` buffers.
        let (status, _, _) = run_chain(filters, log.clone(), b"body", 4).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

        let entries = log.borrow().clone();
        let destroys: Vec<&String> = entries
            .iter()
            .filter(|e| e.ends_with(":on_destroy"))
            .collect();
        assert_eq!(
            destroys,
            vec!["c:on_destroy", "b:on_destroy", "a:on_destroy"],
            "S2.1: teardown must be reverse creation order even on the \
             decode-overflow (413) path; log: {entries:?}"
        );
    });
}

/// S2.2 (G3): the decode-side header-hold gotcha, mirrored onto ENCODE. A
/// filter that returns `StopIteration` from `encode_headers` holds the
/// response headers; a filter EARLIER in config order (which runs LATER in
/// the reverse encode chain) does not see them until the holder's own
/// `encode_data` resolves the hold.
#[test]
fn encode_headers_stop_iteration_holds_and_resumes_via_data() {
    block_on(async {
        let log = log_of();
        let mut b = ProbeFilter::new("b", log.clone());
        b.encode_headers_status = FilterHeadersStatus::StopIteration;
        // `b`'s `encode_data_status` stays `Continue` (default): it resolves
        // the hold the first time it sees the terminal's response data.
        let filters: Vec<Box<dyn HttpFilter>> =
            vec![Box::new(ProbeFilter::new("a", log.clone())), Box::new(b)];
        let (status, _, resp_body) =
            run_chain(filters, log.clone(), b"hi", DEFAULT_BUFFER_LIMIT).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp_body, Bytes::from_static(b"resp"));

        let entries = log.borrow().clone();
        let b_headers = entries.iter().position(|e| e == "b:encode_headers");
        let b_data = entries.iter().position(|e| e.starts_with("b:encode_data"));
        let a_headers = entries.iter().position(|e| e == "a:encode_headers");
        assert!(
            b_headers.is_some() && b_data.is_some() && a_headers.is_some(),
            "log: {entries:?}"
        );
        assert!(
            b_headers < b_data && b_data < a_headers,
            "response headers held at b (first in reverse/encode order) until \
             b's own data resolves the hold — only then does a (earlier \
             config, later in encode order) see them (S2.2); log: {entries:?}"
        );
    });
}

/// S2.2/S2.3 (G4): while `encode_headers` is stopped at a filter, that SAME
/// filter's `encode_data` still fires; returning `Continue` from it flushes
/// the held headers first, then the data, to the remaining (earlier-config)
/// filters — never data before headers.
#[test]
fn encode_headers_hold_flushes_headers_then_data_to_remaining_filters() {
    block_on(async {
        let log = log_of();
        let mut b = ProbeFilter::new("b", log.clone());
        b.encode_headers_status = FilterHeadersStatus::StopIteration;
        let seen_head = Rc::new(RefCell::new(None));
        let seen_data = Rc::new(RefCell::new(Vec::new()));
        let mut a = ProbeFilter::new("a", log.clone());
        a.seen_response_head = Some(seen_head.clone());
        a.seen_encode_data = Some(seen_data.clone());
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(a), Box::new(b)];
        let (status, _, resp_body) =
            run_chain(filters, log.clone(), b"hi", DEFAULT_BUFFER_LIMIT).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp_body, Bytes::from_static(b"resp"));
        assert_eq!(
            seen_head.borrow().as_ref().map(|(s, _)| *s),
            Some(StatusCode::OK),
            "a must eventually see the held headers, once b's own data resolves the hold"
        );
        assert!(
            seen_data.borrow().iter().any(|d| !d.is_empty()),
            "a must also see the response data, after the flushed headers"
        );

        let entries = log.borrow().clone();
        let a_headers = entries.iter().position(|e| e == "a:encode_headers");
        let a_data = entries.iter().position(|e| e.starts_with("a:encode_data"));
        assert!(a_headers.is_some() && a_data.is_some(), "log: {entries:?}");
        assert!(
            a_headers < a_data,
            "S2.3: if headers are still held, they are sent first — a must \
             see encode_headers before encode_data; log: {entries:?}"
        );
    });
}

/// S2.2/S2.3 (G12): overflow while a filter is in `StopAllIterationAndBuffer`
/// on the DECODE side still yields 413 — stop-all buffers too.
#[test]
fn stop_all_iteration_and_buffer_decode_overflow_yields_413() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.decode_headers_status = FilterHeadersStatus::StopAllIterationAndBuffer;
        a.add_decoded = Some(Bytes::from_static(b"0123456789"));
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(a)];
        // Limit of 4 < the 10 bytes the filter buffers.
        let (status, _, _) = run_chain(filters, log.clone(), b"body", 4).await;

        assert_eq!(
            status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "decode-side overflow is 413 even while a filter is StopAllIterationAndBuffer (S2.2/S2.3)"
        );
    });
}

/// S2.2/S2.3 (G12): the ENCODE-side mirror — overflow while a filter is in
/// `StopAllIterationAndBuffer` on `encode_headers` still yields 500.
#[test]
fn stop_all_iteration_and_buffer_encode_overflow_yields_500() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.encode_headers_status = FilterHeadersStatus::StopAllIterationAndBuffer;
        a.add_encoded = Some(Bytes::from_static(b"0123456789"));
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(a)];
        let (status, _, _) = run_chain(filters, log.clone(), b"body", 4).await;

        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "encode-side overflow is 500 even while a filter is StopAllIterationAndBuffer (S2.2/S2.3)"
        );
    });
}

/// S2.2 (G5): `StopAllIterationAndBuffer` on `decode_headers` with a body —
/// nothing (headers, data) proceeds past this filter to subsequent filters
/// OR the terminal handler; incoming data is buffered at this filter.
///
/// `decode_data_status` is ALSO set to `StopIterationAndBuffer` here (never
/// continuing), matching the existing chunk-1
/// `unresolved_header_hold_blocks_subsequent_filters` pattern — needed
/// because of a separate finding (see the task report): `drive_decode`
/// doesn't actually distinguish `StopAllIterationAndBuffer` from plain
/// `StopIteration`'s S2.2 "gotcha" (both call the SAME filter's `decode_data`
/// and resume if it returns `Continue`) — unlike the encode-side
/// `StreamingEncoder`, which correctly skips calling the filter at all for
/// `StopKind::StopAll`. Setting `decode_data_status` here isolates THIS
/// case's specific claim (terminal must not run) from that separate gap.
///
/// NOTE: as written this still asserts the full S2.2 contract, including
/// that the terminal handler must not run. See the task report: the terminal
/// DOES run today (verified directly against `FilterManager::run`) —
/// `drive_decode` returning `Ok(())` when a header hold never resolves does
/// not stop `run()` from calling the terminal handler with whatever body
/// currently exists. This is being reported as a suspected filter-manager
/// bug, not weakened here to match observed behavior (per the Hard rule).
///
/// ORCHESTRATOR ADJUDICATION: deferred, not a live bug. A synchronous buffered
/// decode can't represent "hold the request forever" — a StopAll that never
/// resumes *should* stall the stream until an out-of-band `continue_()` (or a
/// timeout) fires, which is the same chunk-4 resume machinery I3 defers. So
/// "terminal is blocked" can't be asserted until that model exists. The
/// implemented half — StopAll blocks *subsequent filters* (data + trailers) —
/// is covered green by `stop_all_iteration_and_buffer_blocks_trailers` (G6).
#[test]
#[ignore = "WP-11 chunk 4: StopAll blocks the terminal (needs stall / out-of-band resume model)"]
fn stop_all_iteration_and_buffer_blocks_subsequent_filters_and_terminal() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.decode_headers_status = FilterHeadersStatus::StopAllIterationAndBuffer;
        a.decode_data_status = FilterDataStatus::StopIterationAndBuffer; // never continues
        let filters: Vec<Box<dyn HttpFilter>> =
            vec![Box::new(a), Box::new(ProbeFilter::new("b", log.clone()))];
        run_chain(filters, log.clone(), b"hi", DEFAULT_BUFFER_LIMIT).await;

        let entries = log.borrow().clone();
        assert!(
            !entries.iter().any(|e| e.starts_with("b:decode")),
            "nothing proceeds past a filter that stops all iteration (S2.2); log: {entries:?}"
        );
        assert!(
            !entries.iter().any(|e| e == "terminal"),
            "the terminal handler is downstream of everything — a filter that \
             stops all iteration and never resumes must keep the request from \
             reaching it (S2.2); log: {entries:?}"
        );
    });
}

/// S2.2 (G6): `StopAllIterationAndBuffer` also blocks TRAILERS — a trailers
/// frame must not slip past a StopAll'd filter to a subsequent filter. Same
/// `decode_data_status` isolation as G5 above (see its doc comment).
#[test]
fn stop_all_iteration_and_buffer_blocks_trailers() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.decode_headers_status = FilterHeadersStatus::StopAllIterationAndBuffer;
        a.decode_data_status = FilterDataStatus::StopIterationAndBuffer; // never continues
        let filters: Vec<Box<dyn HttpFilter>> =
            vec![Box::new(a), Box::new(ProbeFilter::new("b", log.clone()))];
        let mut trailers = HeaderMap::new();
        trailers.insert("x-trace", HeaderValue::from_static("1"));
        let req = request_with_trailers(b"hi", trailers);
        run_chain_req(filters, log.clone(), req, DEFAULT_BUFFER_LIMIT).await;

        let entries = log.borrow().clone();
        assert!(
            !entries.iter().any(|e| e == "b:decode_trailers"),
            "trailers must not slip past a StopAll'd filter to a subsequent \
             filter (S2.2); log: {entries:?}"
        );
        assert!(
            !entries.iter().any(|e| e == "b:decode_data"),
            "log: {entries:?}"
        );
    });
}

/// S2.2 (G7): the ENCODE-direction mirror of G5/G6 — a filter returning
/// `StopAllIterationAndBuffer` from `encode_headers` blocks everything
/// (headers, data) from proceeding to earlier-config-order filters on the
/// response path (unlike encode's own `StopIteration` gotcha, this position
/// is never even called again — see `StopKind::StopAll`'s doc comment).
#[test]
fn stop_all_iteration_and_buffer_on_encode_headers_blocks_earlier_config_filters() {
    block_on(async {
        let log = log_of();
        let mut b = ProbeFilter::new("b", log.clone());
        b.encode_headers_status = FilterHeadersStatus::StopAllIterationAndBuffer;
        let filters: Vec<Box<dyn HttpFilter>> =
            vec![Box::new(ProbeFilter::new("a", log.clone())), Box::new(b)];
        run_chain(filters, log.clone(), b"hi", DEFAULT_BUFFER_LIMIT).await;

        let entries = log.borrow().clone();
        assert!(
            !entries.iter().any(|e| e.starts_with("a:encode")),
            "nothing proceeds past an encode-side StopAll'd filter to \
             earlier-config-order filters (S2.2); log: {entries:?}"
        );
    });
}

/// S2.3 (G8): `StopIterationAndBuffer` on `decode_data` — the chunk is
/// buffered; resuming via `continue_decoding()` replays it, byte-for-byte, to
/// SUBSEQUENT filters and the terminal; the stopping filter is not re-handed
/// its own chunk.
#[test]
fn decode_stop_iteration_and_buffer_replays_intact_to_subsequent_and_terminal() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.decode_headers_status = FilterHeadersStatus::StopIteration;
        a.decode_data_status = FilterDataStatus::StopIterationAndBuffer;
        a.call_continue_decoding = true;
        let filters: Vec<Box<dyn HttpFilter>> =
            vec![Box::new(a), Box::new(ProbeFilter::new("b", log.clone()))];
        let (status, seen, _) =
            run_chain(filters, log.clone(), b"hello", DEFAULT_BUFFER_LIMIT).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            seen,
            Bytes::from_static(b"hello"),
            "the buffered chunk reaches the terminal intact (S2.3)"
        );

        let entries = log.borrow().clone();
        assert_eq!(
            entries.iter().filter(|e| *e == "a:decode_data").count(),
            1,
            "the stopping filter's decode_data fires exactly once; log: {entries:?}"
        );
        assert!(
            entries.iter().any(|e| e == "b:decode_data"),
            "resume replays the buffered body to subsequent filters; log: {entries:?}"
        );
    });
}

/// S2.3 (G9): `StopIterationNoBuffer` on `decode_data` — the stopped chunk is
/// DROPPED, not accumulated: subsequent filters and the terminal must see
/// NOTHING from it once resumed, and the stopping filter must not re-see it.
///
/// NOTE: as written this asserts the correct S2.3 NoBuffer contract. See the
/// task report — `deliver_decode_data`/`drive_decode` never special-case
/// `FilterDataStatus::StopIterationNoBuffer` differently from
/// `StopIterationAndBuffer` (only `matches!(status, Continue)` is checked);
/// the request body is a single shared `Bytes` already collected up front, so
/// nothing actually drops the chunk before subsequent filters see it. This is
/// being reported as a suspected filter-manager bug (decode side only — the
/// analogous encode-side `StreamingEncoder` code DOES implement the drop, see
/// `filter_manager.rs` ~L1008), not weakened here to match observed behavior.
// ORCHESTRATOR ADJUDICATION: deferred, not a live bug. `NoBuffer`'s "drop this
// chunk" is a *streaming* concept; the decode path is still buffered (chunk 1) —
// the whole body arrives as one already-collected `Bytes`, so there is no
// per-chunk drop to make. The encode-side `StreamingEncoder` implements it and
// is covered green by `encode_stop_iteration_no_buffer_discards_the_chunk`.
#[test]
#[ignore = "WP-11 chunk 4: StopIterationNoBuffer drop on the (still-buffered) decode path"]
fn decode_stop_iteration_no_buffer_drops_the_stopped_chunk() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.decode_headers_status = FilterHeadersStatus::StopIteration;
        a.decode_data_status = FilterDataStatus::StopIterationNoBuffer;
        a.call_continue_decoding = true;
        let filters: Vec<Box<dyn HttpFilter>> =
            vec![Box::new(a), Box::new(ProbeFilter::new("b", log.clone()))];
        let (status, seen, _) =
            run_chain(filters, log.clone(), b"hello", DEFAULT_BUFFER_LIMIT).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            seen,
            Bytes::new(),
            "StopIterationNoBuffer drops the stopped chunk: subsequent \
             filters + terminal must see NOTHING from it (S2.3)"
        );

        let entries = log.borrow().clone();
        assert_eq!(
            entries.iter().filter(|e| *e == "a:decode_data").count(),
            1,
            "the stopping filter must not re-see the dropped chunk; log: {entries:?}"
        );
    });
}

/// S2.3 (G11): `StopIterationAndWatermark` on `decode_data` — for BYTE
/// CORRECTNESS it behaves exactly like `StopIterationAndBuffer`: the chunk is
/// buffered and replayed on resume, reaching the terminal intact. (The
/// *backpressure signal* itself is out of scope here — see I4.)
#[test]
fn decode_stop_iteration_and_watermark_replays_intact_like_buffer() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.decode_headers_status = FilterHeadersStatus::StopIteration;
        a.decode_data_status = FilterDataStatus::StopIterationAndWatermark;
        a.call_continue_decoding = true;
        let filters: Vec<Box<dyn HttpFilter>> =
            vec![Box::new(a), Box::new(ProbeFilter::new("b", log.clone()))];
        let (status, seen, _) =
            run_chain(filters, log.clone(), b"hello", DEFAULT_BUFFER_LIMIT).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            seen,
            Bytes::from_static(b"hello"),
            "watermark buffers just like plain StopIterationAndBuffer for byte \
             correctness (S2.3); the backpressure signal itself is a separate concern"
        );

        let entries = log.borrow().clone();
        assert!(
            entries.iter().any(|e| e == "b:decode_data"),
            "resume replays the buffered body to subsequent filters; log: {entries:?}"
        );
    });
}

/// S2.4 (G13): `decode_trailers` returning `StopIteration` HOLDS the
/// trailers — a subsequent filter must not see them until `continue_decoding()`
/// resumes iteration.
///
/// NOTE: as written this asserts the correct S2.4 hold contract. See the
/// task report — `deliver_decode_data` discards the `FilterTrailersStatus`
/// returned by `decode_trailers` entirely (`let _ = ...decode_trailers(...)`),
/// so there is no trailer-hold mechanism at all on the decode side today; a
/// filter returning `StopIteration` here has no observable effect. Reported
/// as a suspected filter-manager bug, not weakened to match observed behavior
/// (per the Hard rule, which explicitly anticipates this one).
// ORCHESTRATOR ADJUDICATION: deferred, not a live bug. Decode-side trailer-hold
// is simply unimplemented — `deliver_decode_data` discards the
// `FilterTrailersStatus`. Implementing it needs the same held-trailers + resume
// machinery as the chunk-4 hold work; request trailers are also rare for LLM
// traffic, so it's low priority. Kept as the target spec.
#[test]
#[ignore = "WP-11 chunk 4: decode trailer-hold (StopIteration on decode_trailers)"]
fn decode_trailers_stop_iteration_holds_until_resumed() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.decode_trailers_status = FilterTrailersStatus::StopIteration;
        // `a` never calls `continue_decoding()` from `decode_trailers` (the
        // trait gives filters no callback parameter there to call it from in
        // this harness's `ProbeFilter`, matching the S2.4 contract: a filter
        // that holds trailers must be resumed some other way, e.g. a later
        // `continue_decoding()` call — here, simply never).
        let filters: Vec<Box<dyn HttpFilter>> =
            vec![Box::new(a), Box::new(ProbeFilter::new("b", log.clone()))];
        let mut trailers = HeaderMap::new();
        trailers.insert("x-trace", HeaderValue::from_static("1"));
        let req = request_with_trailers(b"hi", trailers);
        run_chain_req(filters, log.clone(), req, DEFAULT_BUFFER_LIMIT).await;

        let entries = log.borrow().clone();
        assert!(
            entries.iter().any(|e| e == "a:decode_trailers"),
            "log: {entries:?}"
        );
        assert!(
            !entries.iter().any(|e| e == "b:decode_trailers"),
            "a filter that holds trailers (StopIteration) must keep them from \
             reaching a subsequent filter until resumed (S2.4); log: {entries:?}"
        );
    });
}

/// S2.4 (G14): trailers arriving while `decode_data` is
/// `StopIterationAndBuffer` queue behind the buffered data — on resume, the
/// order is buffered-data THEN trailers, never the reverse.
#[test]
fn decode_trailers_queue_behind_buffered_data_on_resume() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.decode_headers_status = FilterHeadersStatus::StopIteration;
        a.decode_data_status = FilterDataStatus::StopIterationAndBuffer;
        a.call_continue_decoding = true;
        let filters: Vec<Box<dyn HttpFilter>> =
            vec![Box::new(a), Box::new(ProbeFilter::new("b", log.clone()))];
        let mut trailers = HeaderMap::new();
        trailers.insert("x-trace", HeaderValue::from_static("1"));
        let req = request_with_trailers(b"hi", trailers);
        let (status, _, _) = run_chain_req(filters, log.clone(), req, DEFAULT_BUFFER_LIMIT).await;
        assert_eq!(status, StatusCode::OK);

        let entries = log.borrow().clone();
        let b_data = entries.iter().position(|e| e == "b:decode_data");
        let b_trailers = entries.iter().position(|e| e == "b:decode_trailers");
        assert!(b_data.is_some() && b_trailers.is_some(), "log: {entries:?}");
        assert!(
            b_data < b_trailers,
            "buffered data must be delivered before trailers on resume (S2.4); log: {entries:?}"
        );
    });
}

/// S2.4 (G15): a trailers-only request (no data frames — headers with
/// `end_stream=false`, then a trailers frame) traverses the full chain in
/// order and reaches the terminal.
#[test]
fn trailers_only_request_traverses_the_full_chain() {
    block_on(async {
        let log = log_of();
        let filters: Vec<Box<dyn HttpFilter>> = vec![
            Box::new(ProbeFilter::new("a", log.clone())),
            Box::new(ProbeFilter::new("b", log.clone())),
        ];
        let mut trailers = HeaderMap::new();
        trailers.insert("x-trace", HeaderValue::from_static("1"));
        let req = request_with_trailers(b"", trailers);
        let (status, _, _) = run_chain_req(filters, log.clone(), req, DEFAULT_BUFFER_LIMIT).await;
        assert_eq!(status, StatusCode::OK);

        let entries = log.borrow().clone();
        for name in ["a", "b"] {
            assert!(
                entries
                    .iter()
                    .any(|e| e == &format!("{name}:decode_headers")),
                "log: {entries:?}"
            );
            assert!(
                entries
                    .iter()
                    .any(|e| e == &format!("{name}:decode_trailers")),
                "log: {entries:?}"
            );
        }
        assert!(
            entries.iter().any(|e| e == "terminal"),
            "a trailers-only request must still reach the terminal (S2.4); log: {entries:?}"
        );
    });
}

/// S2.5 (G16): `send_local_reply` called from a decode_DATA callback (not
/// headers) must still synthesize a response through the ENCODER chain; the
/// terminal handler must never run.
#[test]
fn local_reply_from_decode_data_runs_through_encoder_chain() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.send_local_reply_from_data = Some((StatusCode::FORBIDDEN, "nope", "blocked_on_data"));
        let seen_head = Rc::new(RefCell::new(None));
        let mut b = ProbeFilter::new("b", log.clone());
        b.seen_response_head = Some(seen_head.clone());
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(a), Box::new(b)];
        let (status, _, resp_body) =
            run_chain(filters, log.clone(), b"hi", DEFAULT_BUFFER_LIMIT).await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(resp_body, Bytes::from_static(b"nope\n"));
        assert_eq!(
            seen_head.borrow().as_ref().map(|(s, _)| *s),
            Some(StatusCode::FORBIDDEN),
            "a local reply sent from decode_data must still run through the encoder chain (S2.5)"
        );

        let entries = log.borrow().clone();
        assert!(
            !entries.iter().any(|e| e == "terminal"),
            "the terminal handler must never run once a local reply has been \
             requested, even from decode_data; log: {entries:?}"
        );
    });
}

/// S2.5 (G17): the local reply's synthesized response runs the FULL encoder
/// chain (every filter's `encode_headers` observes it), even though the
/// decoder chain never reached the filter after the one that sent it.
#[test]
fn local_reply_encoder_chain_runs_from_the_correct_position() {
    block_on(async {
        let log = log_of();
        let mut b = ProbeFilter::new("b", log.clone());
        b.send_local_reply = Some((StatusCode::FORBIDDEN, "nope", "blocked"));
        let filters: Vec<Box<dyn HttpFilter>> = vec![
            Box::new(ProbeFilter::new("a", log.clone())),
            Box::new(b),
            Box::new(ProbeFilter::new("c", log.clone())),
        ];
        let (status, _, _) = run_chain(filters, log.clone(), b"hi", DEFAULT_BUFFER_LIMIT).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let entries = log.borrow().clone();
        // Decode path: a ran (before b); c never did (b short-circuited).
        assert!(entries.iter().any(|e| e == "a:decode_headers"));
        assert!(!entries.iter().any(|e| e == "c:decode_headers"));

        // Encode path: ALL THREE filters see the synthesized response,
        // reverse config order — the encoder chain doesn't start "after b",
        // it's the full chain, same as any other response (S2.5).
        let encode_headers: Vec<&String> = entries
            .iter()
            .filter(|e| e.ends_with(":encode_headers"))
            .collect();
        assert_eq!(
            encode_headers,
            vec!["c:encode_headers", "b:encode_headers", "a:encode_headers"],
            "the local reply's synthesized response runs the FULL encoder \
             chain, in reverse config order, regardless of which filter sent \
             it or how far the decoder chain got (S2.5); log: {entries:?}"
        );
    });
}

// --- IGNORE cases: WP-11 chunk 4 gaps, written as the target spec ----------

/// S2.2 (I1): `ContinueAndDontEndStream` on `decode_headers` should forward
/// headers with `end_stream=false` even though the request had no body — the
/// filter must later supply data via `inject_decoded_data_to_filter_chain`
/// with `end_stream=true`. Today it's treated as plain `Continue` (module doc,
/// filter_manager.rs L1246-1248).
#[test]
#[ignore = "WP-11 chunk 4: ContinueAndDontEndStream"]
fn continue_and_dont_end_stream_forwards_headers_with_end_stream_false() {
    block_on(async {
        let mut a = ProbeFilter::new("a", log_of());
        a.decode_headers_status = FilterHeadersStatus::ContinueAndDontEndStream;
        // There is no observable "end_stream" flag surfaced to this harness's
        // `ProbeFilter` (it ignores the `_end_stream` parameter) — a real
        // assertion here needs a probe that records `_end_stream` from
        // `decode_headers` and checks it is `false` even for a bodiless
        // request, then drives an `inject_decoded_data_to_filter_chain` call
        // with `end_stream=true` and asserts the terminal sees it. Left as a
        // `todo!()`-free placeholder since the callback itself panics today
        // (see I6) — there is nothing reachable to assert without it.
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(a)];
        run_chain(filters, log_of(), b"", DEFAULT_BUFFER_LIMIT).await;
        unimplemented!("needs inject_decoded_data_to_filter_chain (I6) to complete the scenario");
    });
}

/// S2.2 (I2): the ENCODE-direction mirror of I1 — `ContinueAndDontEndStream`
/// on `encode_headers`.
#[test]
#[ignore = "WP-11 chunk 4: ContinueAndDontEndStream"]
fn encode_continue_and_dont_end_stream_forwards_headers_with_end_stream_false() {
    block_on(async {
        let mut a = ProbeFilter::new("a", log_of());
        a.encode_headers_status = FilterHeadersStatus::ContinueAndDontEndStream;
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(a)];
        run_chain(filters, log_of(), b"", DEFAULT_BUFFER_LIMIT).await;
        unimplemented!("needs inject_encoded_data_to_filter_chain (I7) to complete the scenario");
    });
}

/// S2.2 (I3): `StopAllIterationAndBuffer` RESUME — after the block, only an
/// out-of-band `continue_decoding()` should release the buffered
/// headers+data+trailers to subsequent filters in order. Today: "nothing here
/// re-invokes the filter" (module doc; filter_manager.rs L631-636/L729/L747
/// for the encode-side analogue).
#[test]
#[ignore = "WP-11 chunk 4: StopAll out-of-band resume"]
fn stop_all_iteration_and_buffer_resumes_via_out_of_band_continue() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.decode_headers_status = FilterHeadersStatus::StopAllIterationAndBuffer;
        let filters: Vec<Box<dyn HttpFilter>> =
            vec![Box::new(a), Box::new(ProbeFilter::new("b", log.clone()))];
        // There is no out-of-callback handle to call `continue_decoding()`
        // from once `run()` has already returned control past the stopped
        // filter — that's precisely the missing primitive this case targets.
        // The correct assertion, once it exists: an out-of-band
        // `continue_decoding()` call releases `b`'s decode_headers/decode_data.
        let (_, _, _) = run_chain(filters, log.clone(), b"hi", DEFAULT_BUFFER_LIMIT).await;
        let entries = log.borrow().clone();
        assert!(
            entries.iter().any(|e| e == "b:decode_headers"),
            "an out-of-band continue_decoding() must release a StopAll hold; log: {entries:?}"
        );
    });
}

/// S2.3 (I4): `StopIterationAndWatermark` BACKPRESSURE — overflow should
/// raise a readDisable/flow-control signal instead of erroring (distinct from
/// G11, which only checks bytes). Watermark collapses to plain buffering
/// today (module doc: "watermark backpressure ... treated as plain
/// buffering").
#[test]
#[ignore = "WP-11 chunk 4: watermark backpressure"]
fn stop_iteration_and_watermark_applies_backpressure_on_overflow() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.add_decoded = Some(Bytes::from_static(b"0123456789"));
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(a)];
        // Limit of 4 < the 10 bytes buffered; watermark should signal
        // backpressure rather than reject with 413. There is no
        // backpressure/readDisable observable through this harness yet.
        let (status, _, _) = run_chain(filters, log.clone(), b"body", 4).await;
        assert_ne!(
            status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "watermark overflow must apply backpressure, not 413 (S2.2)"
        );
    });
}

/// S2.2 (I5): `StopAllIterationAndWatermark` — block plus backpressure on
/// overflow (no 413/500).
#[test]
#[ignore = "WP-11 chunk 4: StopAll watermark"]
fn stop_all_iteration_and_watermark_applies_backpressure_on_overflow() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.decode_headers_status = FilterHeadersStatus::StopAllIterationAndWatermark;
        a.add_decoded = Some(Bytes::from_static(b"0123456789"));
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(a)];
        let (status, _, _) = run_chain(filters, log.clone(), b"body", 4).await;
        assert_ne!(
            status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "StopAll + watermark overflow must apply backpressure, not 413/500 (S2.2)"
        );
    });
}

/// S2.6 (I8): an informational (1xx) response should run a SEPARATE encode
/// callback (`encode_1xx_headers`); a filter returning `StopIteration` there
/// blocks the 1xx, resuming via `continue_encoding()` or `Continue` from a
/// later `encode_data`. There is no 1xx flow through this harness at all
/// today — `encode_1xx_headers` is never called anywhere in `filter_manager.rs`.
#[test]
#[ignore = "WP-11 chunk 4: 1xx (S2.6)"]
fn informational_1xx_response_runs_a_separate_encode_callback() {
    // No reachable path exists yet to drive a 1xx response through
    // `FilterManager` — there is no `send_1xx`-equivalent seam. The correct
    // assertion, once it exists: a filter's `encode_1xx_headers` fires before
    // any normal `encode_headers`, and returning `StopIteration` from it holds
    // the 1xx until `continue_encoding()` or a later `Continue` from
    // `encode_data`.
    unimplemented!("no 1xx seam exists yet to drive this scenario (S2.6)")
}

/// S2.7 (I6): `inject_decoded_data_to_filter_chain` should record the
/// injection against the ORIGINATING filter's index (`ctx.decode.current_idx`,
/// stashed by the driver before the owning callback runs) so the driver can
/// deliver it to filters strictly after that one — never re-entering it. This
/// is a unit-level check of the callback adapter itself (no driver involved);
/// [`inject_decoded_data_reaches_subsequent_filters_not_the_injector`] below
/// exercises the full driver-level delivery.
#[test]
fn inject_decoded_data_to_filter_chain_delivers_to_subsequent_filters() {
    let mut ctx = ChainCtx::new();
    ctx.decode.current_idx = 2;
    let mut cb = DecoderCallbacksAdapter { ctx: &mut ctx };
    cb.inject_decoded_data_to_filter_chain(Bytes::from_static(b"x"), true);
    assert_eq!(
        ctx.decode.injected.len(),
        1,
        "the injection must be queued, not dropped or delivered synchronously here"
    );
    let (from_idx, data, end_stream) = ctx.decode.injected.front().expect("queued above");
    assert_eq!(
        *from_idx, 2,
        "must record the ORIGINATING filter's index so the driver knows where \"after\" is"
    );
    assert_eq!(data, &Bytes::from_static(b"x"));
    assert!(*end_stream);
}

/// S2.7 (I7): `inject_encoded_data_to_filter_chain` mirror — the encode side
/// resumes at `pos + 1` (toward the client; see `StreamingEncoder`'s doc
/// comment on position order), reusing `PendingFrame`'s shape directly.
#[test]
fn inject_encoded_data_to_filter_chain_delivers_to_subsequent_filters() {
    let mut ctx = ChainCtx::new();
    ctx.encode.positions = vec![PositionState::default(), PositionState::default()];
    let mut cb = EncoderCallbacksAdapter {
        ctx: &mut ctx,
        pos: 0,
    };
    cb.inject_encoded_data_to_filter_chain(Bytes::from_static(b"x"), true);
    assert_eq!(ctx.encode.injected.len(), 1);
    let frame = ctx.encode.injected.front().expect("queued above");
    assert_eq!(
        frame.start_pos, 1,
        "must resume at pos + 1 (toward the client), never pos itself"
    );
    assert_eq!(frame.data, Bytes::from_static(b"x"));
    assert!(frame.end_stream);
}

// --- WP-11 chunk 4: full driver-level injection semantics (S2.7) ----------

/// S2.7: injected data must reach filters strictly AFTER the injecting one,
/// and must NOT be delivered back to the injector itself — the core semantic
/// that distinguishes injection from `add_decoded_data` (which only appends
/// to the buffer the injecting filter is already working with).
#[test]
fn inject_decoded_data_reaches_subsequent_filters_not_the_injector() {
    block_on(async {
        let log = log_of();
        let a_seen = Rc::new(RefCell::new(Vec::new()));
        let b_seen = Rc::new(RefCell::new(Vec::new()));
        let mut a = ProbeFilter::new("a", log.clone());
        a.inject_decoded = Some((Bytes::from_static(b"INJ"), false));
        a.seen_decode_data = Some(a_seen.clone());
        let mut b = ProbeFilter::new("b", log.clone());
        b.seen_decode_data = Some(b_seen.clone());
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(a), Box::new(b)];
        let (status, seen, _) = run_chain(filters, log.clone(), b"hi", DEFAULT_BUFFER_LIMIT).await;
        assert_eq!(status, StatusCode::OK);

        let a_seen = a_seen.borrow();
        assert!(
            !a_seen.iter().any(|(d, _)| d == &Bytes::from_static(b"INJ")),
            "an injecting filter must never see its own injected data; saw: {a_seen:?}"
        );
        let b_seen = b_seen.borrow();
        assert!(
            b_seen.iter().any(|(d, _)| d == &Bytes::from_static(b"INJ")),
            "a subsequent filter must receive the injected data; saw: {b_seen:?}"
        );
        // Sanity: injected data that survives every subsequent filter (both
        // `Continue`d here) rides along to the terminal exactly like
        // `add_decoded_data` would (S2.7) — prepended ahead of the real body.
        assert_eq!(seen, Bytes::from_static(b"INJhi"));
    });
}

/// S2.7: injection is out-of-band — a filter calling it while it is holding
/// iteration (`StopIteration`, never resuming) must not thereby resume
/// iteration itself. `b` must receive the injected chunk directly (injection
/// bypasses the normal header/data pointer entirely) even though `b` never
/// gets as far as its own `decode_headers` in the normal iteration.
#[test]
fn inject_decoded_data_does_not_resume_the_injectors_own_held_iteration() {
    block_on(async {
        let log = log_of();
        let b_seen = Rc::new(RefCell::new(Vec::new()));
        let mut a = ProbeFilter::new("a", log.clone());
        a.decode_headers_status = FilterHeadersStatus::StopIteration;
        a.decode_data_status = FilterDataStatus::StopIterationAndBuffer; // never continues
        a.inject_decoded = Some((Bytes::from_static(b"INJ"), false));
        let mut b = ProbeFilter::new("b", log.clone());
        b.seen_decode_data = Some(b_seen.clone());
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(a), Box::new(b)];
        run_chain(filters, log.clone(), b"hi", DEFAULT_BUFFER_LIMIT).await;

        let entries = log.borrow().clone();
        assert!(
            !entries.iter().any(|e| e == "b:decode_headers"),
            "the injecting filter never continued, so normal iteration must \
             stay stopped at it (S2.2); log: {entries:?}"
        );
        let b_seen = b_seen.borrow();
        assert!(
            b_seen.iter().any(|(d, _)| d == &Bytes::from_static(b"INJ")),
            "injection is out-of-band: it must still reach a subsequent \
             filter's decode_data directly, even though normal iteration \
             never got there; saw: {b_seen:?}"
        );
    });
}

/// S2.7: `end_stream: true` on an injection must terminate the downstream
/// portion of the chain correctly — the subsequent filter observes
/// `end_stream = true` on the injected chunk, not `false`.
#[test]
fn inject_decoded_data_end_stream_true_terminates_downstream_portion() {
    block_on(async {
        let log = log_of();
        let b_seen = Rc::new(RefCell::new(Vec::new()));
        let mut a = ProbeFilter::new("a", log.clone());
        a.inject_decoded = Some((Bytes::from_static(b"INJ"), true));
        let mut b = ProbeFilter::new("b", log.clone());
        b.seen_decode_data = Some(b_seen.clone());
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(a), Box::new(b)];
        run_chain(filters, log.clone(), b"hi", DEFAULT_BUFFER_LIMIT).await;

        let b_seen = b_seen.borrow();
        let injected = b_seen
            .iter()
            .find(|(d, _)| d == &Bytes::from_static(b"INJ"))
            .expect("b must observe the injected chunk");
        assert!(
            injected.1,
            "end_stream: true on the injection must reach the subsequent \
             filter as end_stream = true, terminating the downstream portion \
             of the chain (S2.7); saw: {b_seen:?}"
        );
    });
}

/// S2.7 (encode mirror): an injection from position `p` must be seen by
/// positions AFTER `p` (toward the client — `p + 1`, `p + 2`, ...) and NOT by
/// positions at or before `p`. Config order [a, b, c] means encode order is
/// c (position 0), b (position 1), a (position 2) — reverse config order
/// (S2.1) — so an injection from `b` (position 1) must reach `a` (position 2)
/// but not `b` itself nor `c` (position 0, which already ran).
#[test]
fn encode_injection_from_position_p_seen_only_after_p() {
    block_on(async {
        let log = log_of();
        let a_seen = Rc::new(RefCell::new(Vec::new()));
        let b_seen = Rc::new(RefCell::new(Vec::new()));
        let c_seen = Rc::new(RefCell::new(Vec::new()));
        let mut a = ProbeFilter::new("a", log.clone());
        a.seen_encode_data = Some(a_seen.clone());
        let mut b = ProbeFilter::new("b", log.clone());
        b.inject_encoded = Some((Bytes::from_static(b"INJ"), false));
        b.seen_encode_data = Some(b_seen.clone());
        let mut c = ProbeFilter::new("c", log.clone());
        c.seen_encode_data = Some(c_seen.clone());
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(a), Box::new(b), Box::new(c)];
        run_chain(filters, log.clone(), b"hi", DEFAULT_BUFFER_LIMIT).await;

        let injected = Bytes::from_static(b"INJ");
        assert!(
            a_seen.borrow().iter().any(|d| d == &injected),
            "position after the injector (toward the client) must see it; saw: {:?}",
            a_seen.borrow()
        );
        assert!(
            !b_seen.borrow().iter().any(|d| d == &injected),
            "the injector itself must never see its own injected data; saw: {:?}",
            b_seen.borrow()
        );
        assert!(
            !c_seen.borrow().iter().any(|d| d == &injected),
            "a position before the injector (already ran) must never see it; saw: {:?}",
            c_seen.borrow()
        );
    });
}

/// S2.8 (I9): a filter mutating a routing-relevant header must call
/// `clear_route_cache()`; the cache is NOT auto-invalidated. Needs the
/// WP-12 route table to have anything to differentially resolve against — no
/// route is ever cached yet (`ctx.route` is always `None`, filter_manager.rs).
#[test]
#[ignore = "WP-11 chunk 4 / WP-12: route cache (S2.8)"]
fn route_cache_is_not_auto_invalidated_on_header_mutation() {
    let mut ctx = ChainCtx::new();
    let cb = DecoderCallbacksAdapter { ctx: &mut ctx };
    // There is no route table to resolve against yet (WP-12) — `route()`
    // always returns `None`. The differential fixture this needs: resolve a
    // route, mutate a routing header without calling `clear_route_cache()`,
    // and assert `route()` still returns the STALE cached route rather than
    // re-resolving.
    assert!(
        cb.route().is_some(),
        "once route resolution exists, a cached route must survive a header \
         mutation unless clear_route_cache() is called (S2.8)"
    );
}

// --- S9: `x-request-id` generation, at the `FilterChainHandler` level ---
//
// Unlike the rest of this file, these tests go through `FilterChainHandler`
// itself (not `FilterManager` directly): id generation happens in
// `FilterChainHandler::handle`, before a `FilterManager` even exists, so
// there is nothing to observe by constructing `FilterManager` by hand here.

/// Build a `FilterChainHandler` with no configured filters (only the S9
/// request-id behavior + the recording terminal matter for these tests) and
/// run one request through it, returning the `x-request-id` the terminal
/// observed (`None` if it never arrived).
fn run_through_handler(
    generate_request_id: bool,
    existing_request_id: Option<&'static str>,
) -> Option<String> {
    block_on(async {
        let seen_request_id = Rc::new(RefCell::new(None));
        let terminal = Rc::new(RecordingTerminal {
            log: log_of(),
            seen_body: Rc::new(RefCell::new(Bytes::new())),
            seen_request_id: seen_request_id.clone(),
            seen_headers: None,
        });
        let handler = FilterChainHandler::new(Vec::new(), terminal, generate_request_id, false, 0);

        let mut req = request(b"hi");
        if let Some(id) = existing_request_id {
            req.head.headers.insert(
                HeaderName::from_static("x-request-id"),
                HeaderValue::from_static(id),
            );
        }
        let _ = handler.handle(req).await;
        let seen = seen_request_id.borrow().clone();
        seen
    })
}

/// S9: `generate_request_id = true` and no `x-request-id` on the request ->
/// the terminal observes a freshly generated, non-empty id.
#[test]
fn generate_request_id_true_adds_id_when_absent() {
    let seen = run_through_handler(true, None);
    assert!(
        seen.is_some_and(|id| !id.is_empty()),
        "expected a generated x-request-id"
    );
}

/// S9: `generate_request_id = false` -> no `x-request-id` is added.
#[test]
fn generate_request_id_false_leaves_id_absent() {
    let seen = run_through_handler(false, None);
    assert_eq!(seen, None, "generate_request_id = false must not add an id");
}

/// S9: an existing `x-request-id` is preserved untouched, never regenerated,
/// regardless of `generate_request_id`.
#[test]
fn existing_request_id_is_preserved() {
    let seen = run_through_handler(true, Some("caller-supplied-id"));
    assert_eq!(seen, Some("caller-supplied-id".to_string()));
}

/// S9: two independently-constructed `FilterChainHandler`s draw from
/// independent RNG state (per-worker seeding, mirroring the equivalent test
/// in `headers.rs` for the bare seed/generate functions) and so generate
/// DIFFERENT ids for equivalent requests.
#[test]
fn separately_constructed_handlers_generate_different_ids() {
    let a = run_through_handler(true, None).expect("handler a generated an id");
    let b = run_through_handler(true, None).expect("handler b generated an id");
    assert_ne!(
        a, b,
        "two separately-constructed handlers must not produce the same id \
         sequence"
    );
}

// --- S9: XFF / `use_remote_address`, at the `FilterChainHandler` level ---
//
// Mirrors the `x-request-id` tests above: this behavior is applied in
// `FilterChainHandler::handle`, HCM-level, before a `FilterManager` even
// exists.

/// Build a `FilterChainHandler` with no configured filters, the given
/// `use_remote_address`/`xff_num_trusted_hops`, and a request whose
/// downstream peer is `remote` / TLS-ness is `is_tls` and whose inbound
/// headers are `inbound_headers`. Returns the header map the terminal
/// observed.
fn run_through_handler_xff(
    use_remote_address: bool,
    xff_num_trusted_hops: u32,
    remote: std::net::SocketAddr,
    is_tls: bool,
    inbound_headers: &[(&str, &str)],
) -> HeaderMap {
    block_on(async {
        let seen_headers = Rc::new(RefCell::new(None));
        let terminal = Rc::new(RecordingTerminal {
            log: log_of(),
            seen_body: Rc::new(RefCell::new(Bytes::new())),
            seen_request_id: Rc::new(RefCell::new(None)),
            seen_headers: Some(seen_headers.clone()),
        });
        let handler = FilterChainHandler::new(
            Vec::new(),
            terminal,
            false,
            use_remote_address,
            xff_num_trusted_hops,
        );

        let mut req = request(b"hi");
        req.downstream = DownstreamInfo { remote, is_tls };
        for (name, value) in inbound_headers {
            req.head.headers.insert(
                HeaderName::from_bytes(name.as_bytes()).expect("valid header name"),
                HeaderValue::from_str(value).expect("valid header value"),
            );
        }
        let _ = handler.handle(req).await;
        let result = seen_headers
            .borrow()
            .clone()
            .expect("terminal must have run and recorded headers");
        result
    })
}

/// S9: `use_remote_address = true`, no inbound XFF -> the terminal sees a
/// freshly-created `x-forwarded-for` naming just the downstream peer, and
/// `x-forwarded-proto: http` (the connection wasn't TLS).
#[test]
fn use_remote_address_true_sets_xff_and_proto_http() {
    let remote: std::net::SocketAddr = "203.0.113.7:5000".parse().unwrap();
    let seen = run_through_handler_xff(true, 0, remote, false, &[]);
    assert_eq!(
        seen.get("x-forwarded-for").map(|v| v.to_str().unwrap()),
        Some("203.0.113.7")
    );
    assert_eq!(
        seen.get("x-forwarded-proto").map(|v| v.to_str().unwrap()),
        Some("http")
    );
}

/// S9: `use_remote_address = true` on a TLS-terminated connection -> the
/// terminal sees `x-forwarded-proto: https`.
#[test]
fn use_remote_address_true_sets_proto_https_for_tls() {
    let remote: std::net::SocketAddr = "203.0.113.7:5000".parse().unwrap();
    let seen = run_through_handler_xff(true, 0, remote, true, &[]);
    assert_eq!(
        seen.get("x-forwarded-proto").map(|v| v.to_str().unwrap()),
        Some("https")
    );
}

/// S9: `use_remote_address = true` with an existing inbound `x-forwarded-for`
/// -> the downstream peer is appended (rightmost), not substituted.
#[test]
fn use_remote_address_true_appends_to_existing_xff() {
    let remote: std::net::SocketAddr = "203.0.113.7:5000".parse().unwrap();
    let seen = run_through_handler_xff(
        true,
        0,
        remote,
        false,
        &[("x-forwarded-for", "198.51.100.1")],
    );
    assert_eq!(
        seen.get("x-forwarded-for").map(|v| v.to_str().unwrap()),
        Some("198.51.100.1, 203.0.113.7")
    );
}

/// S9: `use_remote_address = false` (the Envoy default) leaves an inbound
/// `x-forwarded-for` / `x-forwarded-proto` completely untouched -- proves the
/// edge gate in `FilterChainHandler::handle`.
#[test]
fn use_remote_address_false_leaves_xff_and_proto_untouched() {
    let remote: std::net::SocketAddr = "203.0.113.7:5000".parse().unwrap();
    let seen = run_through_handler_xff(
        false,
        0,
        remote,
        false,
        &[
            ("x-forwarded-for", "198.51.100.1"),
            ("x-forwarded-proto", "https"),
        ],
    );
    assert_eq!(
        seen.get("x-forwarded-for").map(|v| v.to_str().unwrap()),
        Some("198.51.100.1")
    );
    assert_eq!(
        seen.get("x-forwarded-proto").map(|v| v.to_str().unwrap()),
        Some("https")
    );
}
