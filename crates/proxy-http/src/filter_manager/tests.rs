//! WP-11 chunk 1 tests: the S2 mechanics this chunk implements. The exhaustive
//! status-matrix conformance suite is chunk 2; these pin the engine's spine —
//! ordering (S2.1), the header-hold gotcha (S2.2), data statuses (S2.3),
//! trailers (S2.4), the buffer APIs (S2.7), and overflow → 413/500.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use http_body_util::BodyExt;
use proxy_config::ir::{
    AccessLogFormat, AccessLogSink, ForwardAction, ForwardTarget, PathMatch, RouteActionIR,
    RouteEntry, RouteMatcher, RouteTable, VirtualHostIR,
};
use proxy_observability::access_log::parse_format;

use super::*;
use crate::filter::{FactoryContext, FilterTrailersStatus, RequestHeaders};
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

/// A route table with no virtual hosts, for tests that need to hand
/// `FilterChainHandler` SOME table (it's a required field, S2.8) but don't
/// exercise routing themselves -- `route()` then always returns `None`,
/// matching this suite's pre-S2.8 behavior everywhere except the tests below
/// that build their own real table.
fn empty_route_table() -> Arc<RouteTable> {
    Arc::new(
        RouteTable::new("test-routes".to_string(), Vec::new(), BTreeMap::new())
            .expect("empty table is valid"),
    )
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
    /// ADR-0004 step 2 test hook: the request headers this filter observed in
    /// `decode_headers`, so a test can assert a mutation made by an EARLIER
    /// async filter (during its resumption) is visible here.
    seen_decode_headers: Option<Rc<RefCell<Option<HeaderMap>>>>,
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
            seen_decode_headers: None,
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
        headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        self.record("decode_headers");
        if let Some(seen) = &self.seen_decode_headers {
            *seen.borrow_mut() = Some(headers.headers.clone());
        }
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
    let seen_body = Arc::new(Mutex::new(Bytes::new()));
    let terminal = RecordingTerminal {
        log: log.clone(),
        term_log: None,
        seen_body: seen_body.clone(),
        seen_request_id: Arc::new(Mutex::new(None)),
        seen_headers: None,
        captured_body: Bytes::new(),
    };
    let mgr = FilterManager {
        filters,
        ctx: ChainCtx::new(Rc::new(RefCell::new(StreamInfo::default()))),
        terminal: Box::new(terminal),
        buffer_limit,
    };
    let resp = mgr.run(req).await;
    let status = resp.head.status;
    let resp_body = resp.body.collect().await.expect("resp body").to_bytes();
    let seen = seen_body.lock().unwrap().clone();
    (status, seen, resp_body)
}

/// Like [`run_chain_req`], but with a real route table attached to `ctx`
/// (S2.8) -- for the route-resolution tests below, which need `route()` to
/// resolve against something rather than always returning `None`.
async fn run_chain_req_with_route_table(
    filters: Vec<Box<dyn HttpFilter>>,
    log: Log,
    req: HttpRequestParts,
    route_table: Arc<RouteTable>,
) -> StatusCode {
    let seen_body = Arc::new(Mutex::new(Bytes::new()));
    let terminal = RecordingTerminal {
        log,
        term_log: None,
        seen_body,
        seen_request_id: Arc::new(Mutex::new(None)),
        seen_headers: None,
        captured_body: Bytes::new(),
    };
    let mgr = FilterManager {
        filters,
        ctx: ChainCtx::new(Rc::new(RefCell::new(StreamInfo::default())))
            .with_route_table(route_table),
        terminal: Box::new(terminal),
        buffer_limit: DEFAULT_BUFFER_LIMIT,
    };
    let resp = mgr.run(req).await;
    let status = resp.head.status;
    let _ = resp.body.collect().await;
    status
}

/// A terminal filter that records that it ran and echoes a fixed 200 with the
/// request body it received (so tests can assert what reached the router).
///
/// ADR-0004 step 3: this is now an ordinary [`HttpFilter`] (capturing what it
/// needs from `decode_headers`/`decode_data` -- exactly like `RouterHandler`
/// does) plus [`TerminalHttpFilter::respond`], rather than a bespoke
/// `StreamHandler` handed a whole `HttpRequestParts` across a seam.
struct RecordingTerminal {
    log: Log,
    /// Mirrors [`Self::respond`]'s `"terminal"` push into a `Send + Sync`
    /// sink too, when this instance was minted by [`RecordingTerminalFactory`]
    /// (which -- unlike `log`'s `Rc`, deliberately shared with `ProbeFilter`
    /// so their entries interleave in one ordered call log -- must itself be
    /// `Send + Sync` per ADR-0003/[`TerminalFilterInstanceFactory`]'s doc).
    /// `None` for the `run_chain*` helpers below, which construct this
    /// instance directly and read `log` itself instead.
    term_log: Option<Arc<Mutex<Vec<String>>>>,
    seen_body: Arc<Mutex<Bytes>>,
    /// S9 test hook: the `x-request-id` the terminal observed on the request
    /// head (mirrors `seen_body` above), so `FilterChainHandler`-level tests
    /// can assert what the router saw after the HCM-level id generation ran.
    seen_request_id: Arc<Mutex<Option<String>>>,
    /// S9 XFF test hook: the full request header map the terminal observed,
    /// so `FilterChainHandler`-level XFF tests can assert what
    /// `x-forwarded-for` / `x-forwarded-proto` looked like after the
    /// HCM-level mutation ran. `None` when the test doesn't care (most
    /// callers below).
    seen_headers: Option<Arc<Mutex<Option<HeaderMap>>>>,
    /// Captured in `decode_data`, consumed by `respond`.
    captured_body: Bytes,
}

impl HttpFilter for RecordingTerminal {
    fn decode_headers(
        &mut self,
        _cb: &mut dyn DecoderCallbacks,
        headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        *self.seen_request_id.lock().unwrap() = headers
            .headers
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        if let Some(seen_headers) = &self.seen_headers {
            *seen_headers.lock().unwrap() = Some(headers.headers.clone());
        }
        FilterHeadersStatus::Continue
    }

    fn decode_data(
        &mut self,
        _cb: &mut dyn DecoderCallbacks,
        data: &mut Bytes,
        _end_stream: bool,
    ) -> FilterDataStatus {
        self.captured_body = data.clone();
        FilterDataStatus::Continue
    }

    /// ADR-0004 step 3: the terminal is now an ordinary filter instance
    /// (`filter_manager::destroy_filters` calls `terminal.on_destroy()`
    /// before walking the rest of the chain in reverse creation order) --
    /// before this step the router lived behind a `StreamHandler` seam and
    /// never received `on_destroy` at all. Recorded onto the same shared
    /// `Log` every `ProbeFilter` writes to, so a test can assert both that
    /// it fires and where it falls in the overall teardown order.
    fn on_destroy(&mut self) {
        self.log
            .borrow_mut()
            .push("terminal:on_destroy".to_string());
    }
}

impl TerminalHttpFilter for RecordingTerminal {
    fn respond<'a>(
        &'a mut self,
        _cb: &'a mut dyn DecoderCallbacks,
    ) -> Pin<Box<dyn Future<Output = HttpResponseParts> + 'a>> {
        Box::pin(async move {
            self.log.borrow_mut().push("terminal".to_string());
            if let Some(term_log) = &self.term_log {
                term_log.lock().unwrap().push("terminal".to_string());
            }
            *self.seen_body.lock().unwrap() = self.captured_body.clone();
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

/// ADR-0004 step 3: [`RecordingTerminal`]'s own factory, for the
/// `FilterChainHandler`-level tests below -- mints a fresh instance per
/// request, sharing the same observation handles so the test can still read
/// what the (fresh) instance saw. `Send + Sync`, per
/// `TerminalFilterInstanceFactory`'s doc (ADR-0003: config-time plumbing
/// crosses threads), so every field is an `Arc<Mutex<_>>`, unlike
/// `RecordingTerminal`'s own `log`, which stays a plain `Rc` -- shared with
/// `ProbeFilter`, which has no such requirement (see `Log`'s doc) -- so
/// factory-minted instances get a private, throwaway `log` of their own
/// (`create_terminal_filter` below) and mirror what matters into `term_log`
/// instead.
struct RecordingTerminalFactory {
    seen_body: Arc<Mutex<Bytes>>,
    seen_request_id: Arc<Mutex<Option<String>>>,
    seen_headers: Option<Arc<Mutex<Option<HeaderMap>>>>,
    /// See [`RecordingTerminal::term_log`]. `None` when a test doesn't care
    /// whether the terminal ran.
    term_log: Option<Arc<Mutex<Vec<String>>>>,
}

impl TerminalFilterInstanceFactory for RecordingTerminalFactory {
    fn create_terminal_filter(&self) -> Box<dyn TerminalHttpFilter> {
        Box::new(RecordingTerminal {
            // Fresh and private: factory-minted instances are never run
            // alongside a `ProbeFilter`, so there's nothing to interleave
            // with -- see the struct doc above.
            log: log_of(),
            term_log: self.term_log.clone(),
            seen_body: self.seen_body.clone(),
            seen_request_id: self.seen_request_id.clone(),
            seen_headers: self.seen_headers.clone(),
            captured_body: Bytes::new(),
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
    let seen_body = Arc::new(Mutex::new(Bytes::new()));
    let terminal = RecordingTerminal {
        log: log.clone(),
        term_log: None,
        seen_body: seen_body.clone(),
        seen_request_id: Arc::new(Mutex::new(None)),
        seen_headers: None,
        captured_body: Bytes::new(),
    };
    let mgr = FilterManager {
        filters,
        ctx: ChainCtx::new(Rc::new(RefCell::new(StreamInfo::default()))),
        terminal: Box::new(terminal),
        buffer_limit,
    };
    let resp = mgr.run(request(body)).await;
    let status = resp.head.status;
    let resp_body = resp.body.collect().await.expect("resp body").to_bytes();
    let seen = seen_body.lock().unwrap().clone();
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
            vec!["terminal:on_destroy", "b:on_destroy", "a:on_destroy"],
            "instances destroyed in reverse creation order (S2.1), the \
             terminal being created LAST and so destroyed FIRST; \
             log: {entries:?}"
        );
    });
}

/// ADR-0004 step 3: the terminal is now an ordinary [`HttpFilter`] instance
/// living in the chain (created LAST, after every configured filter), so per
/// the `HttpFilter` contract -- instances destroyed in reverse creation order
/// (S2.1) -- it must receive `on_destroy` exactly like any other filter. It
/// never could before this step: the router sat behind a bespoke
/// `StreamHandler` seam that had no teardown hook at all. Two `ProbeFilter`s
/// bracket the terminal so the full reverse-creation-order sequence is
/// observable, not just "it fires at all".
#[test]
fn terminal_receives_on_destroy_in_reverse_creation_order() {
    block_on(async {
        let log = log_of();
        let filters: Vec<Box<dyn HttpFilter>> = vec![
            Box::new(ProbeFilter::new("a", log.clone())),
            Box::new(ProbeFilter::new("b", log.clone())),
        ];
        let (status, _, _) = run_chain(filters, log.clone(), b"hi", DEFAULT_BUFFER_LIMIT).await;
        assert_eq!(status, StatusCode::OK);

        let entries = log.borrow().clone();
        let destroys: Vec<&String> = entries
            .iter()
            .filter(|e| e.ends_with(":on_destroy"))
            .collect();
        assert_eq!(
            destroys,
            vec!["terminal:on_destroy", "b:on_destroy", "a:on_destroy"],
            "the terminal is created LAST (position n, after `a` and `b`), so \
             it must be destroyed FIRST -- reverse creation order (S2.1); \
             log: {entries:?}"
        );
        assert_eq!(
            entries
                .iter()
                .filter(|e| *e == "terminal:on_destroy")
                .count(),
            1,
            "on_destroy must fire exactly once per stream; log: {entries:?}"
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
    let mut ctx = ChainCtx::new(Rc::new(RefCell::new(StreamInfo::default())));
    {
        let mut cb = DecoderCallbacksAdapter::new(&mut ctx);
        cb.send_local_reply(StatusCode::FORBIDDEN, "nope", None, "custom_reason");
    }
    assert!(ctx.stream_info.borrow().is_local_reply);
    assert_eq!(
        ctx.stream_info.borrow().response_code_details.as_deref(),
        Some("custom_reason")
    );
    assert!(ctx.local_reply.is_some());
}

/// A second `send_local_reply` while one is already pending is ignored —
/// first one wins (matches Envoy).
#[test]
fn a_second_local_reply_is_ignored() {
    let mut ctx = ChainCtx::new(Rc::new(RefCell::new(StreamInfo::default())));
    {
        let mut cb = DecoderCallbacksAdapter::new(&mut ctx);
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
        ctx.stream_info.borrow().response_code_details.as_deref(),
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
            vec![
                "terminal:on_destroy",
                "c:on_destroy",
                "b:on_destroy",
                "a:on_destroy"
            ],
            "S2.1 reverse creation-order teardown, terminal (created last) first; \
             log: {entries:?}"
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
            vec![
                "terminal:on_destroy",
                "c:on_destroy",
                "b:on_destroy",
                "a:on_destroy"
            ],
            "S2.1: teardown must be reverse creation order even on the \
             local-reply short-circuit path, terminal (created last) first; \
             log: {entries:?}"
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
            vec![
                "terminal:on_destroy",
                "c:on_destroy",
                "b:on_destroy",
                "a:on_destroy"
            ],
            "S2.1: teardown must be reverse creation order even on the \
             decode-overflow (413) path, terminal (created last) first; \
             log: {entries:?}"
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

/// S2.4/chunk 4 (G13): `decode_trailers` returning `StopIteration` HOLDS the
/// trailers — a subsequent filter must not see them until `continue_decoding()`
/// resumes iteration. `deliver_decode_data` now checks the
/// `FilterTrailersStatus` it gets back (previously discarded via
/// `let _ = ...decode_trailers(...)`) and reports "not continued" up to
/// `drive_decode`, which stops delivering to later filters exactly like an
/// unresolved header/data hold already does.
#[test]
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

/// A filter that returns `ContinueAndDontEndStream` from `decode_headers` and
/// supplies the body itself, out of band, exactly as S2.2 (I1) requires.
struct DontEndStreamThenInjectFilter {
    injected: Bytes,
}

impl HttpFilter for DontEndStreamThenInjectFilter {
    fn decode_headers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        _h: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        cb.inject_decoded_data_to_filter_chain(self.injected.clone(), true);
        FilterHeadersStatus::ContinueAndDontEndStream
    }
}

/// Records the `end_stream` flag it was handed on `decode_headers`, which is
/// the whole observable of I1 and the one thing `ProbeFilter` throws away.
struct RecordsHeaderEndStreamFilter {
    seen: Arc<Mutex<Option<bool>>>,
}

impl HttpFilter for RecordsHeaderEndStreamFilter {
    fn decode_headers(
        &mut self,
        _cb: &mut dyn DecoderCallbacks,
        _h: &mut RequestHeaders,
        end_stream: bool,
    ) -> FilterHeadersStatus {
        *self.seen.lock().unwrap() = Some(end_stream);
        FilterHeadersStatus::Continue
    }
}

/// S2.2 (I1): `ContinueAndDontEndStream` on `decode_headers` forwards headers
/// with `end_stream=false` even though the request had no body -- the filter
/// has taken responsibility for supplying it via
/// `inject_decoded_data_to_filter_chain` with `end_stream=true`.
///
/// The bodiless request is what makes this a real test rather than a tautology:
/// `end_stream_on_headers` is `body.is_empty() && trailers.is_none()`, so
/// without the status it is unambiguously `true` here. Treating the status as
/// plain `Continue` -- which is what the driver did until this landed -- leaves
/// it `true`, and the filter behind gets told the stream is over while data is
/// still on its way.
#[test]
fn continue_and_dont_end_stream_forwards_headers_with_end_stream_false() {
    block_on(async {
        let seen = Arc::new(Mutex::new(None));
        let filters: Vec<Box<dyn HttpFilter>> = vec![
            Box::new(DontEndStreamThenInjectFilter {
                injected: Bytes::from_static(b"late body"),
            }),
            Box::new(RecordsHeaderEndStreamFilter { seen: seen.clone() }),
        ];
        // `b""` -- no request body at all.
        let (status, seen_body, _) = run_chain(filters, log_of(), b"", DEFAULT_BUFFER_LIMIT).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            *seen.lock().unwrap(),
            Some(false),
            "the filter behind the sender must be told the stream is NOT over, \
             even though the request carried no body"
        );
        assert_eq!(
            seen_body,
            Bytes::from_static(b"late body"),
            "the out-of-band injection must still reach the terminal as the body"
        );
    });
}

/// A terminal that records the `end_stream` it was handed on `decode_headers`.
/// `RecordingTerminal` discards it, and the terminal's flag is computed at a
/// SEPARATE site in `run()` from the one `drive_decode` uses -- so observing
/// the filters' view proves nothing about the terminal's.
struct EndStreamRecordingTerminal {
    seen: Arc<Mutex<Option<bool>>>,
}

impl HttpFilter for EndStreamRecordingTerminal {
    fn decode_headers(
        &mut self,
        _cb: &mut dyn DecoderCallbacks,
        _h: &mut RequestHeaders,
        end_stream: bool,
    ) -> FilterHeadersStatus {
        *self.seen.lock().unwrap() = Some(end_stream);
        FilterHeadersStatus::Continue
    }
}

impl TerminalHttpFilter for EndStreamRecordingTerminal {
    fn respond<'a>(
        &'a mut self,
        _cb: &'a mut dyn DecoderCallbacks,
    ) -> Pin<Box<dyn Future<Output = HttpResponseParts> + 'a>> {
        Box::pin(async move {
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

/// The terminal is the last filter in the decode chain (ADR-0004 step 3), so it
/// must see the same `end_stream=false` the configured filters behind the
/// sender saw. Its flag is computed at its own site in `run()`, so it is
/// genuinely possible to fix one and not the other -- hence its own test, with
/// a terminal that actually records the flag rather than a filter standing in
/// for one.
///
/// The injection is deliberately EMPTY, and that is the whole design of this
/// test. A non-empty one lands in the decode buffer, which makes
/// `decoded_body.is_empty()` false and hands the terminal `end_stream=false`
/// for a reason that has nothing to do with the status -- the first version of
/// this test did exactly that and stayed green when the clause under test was
/// deleted. An empty injection is still a legitimate filter: it said it would
/// supply the body and supplied an empty one, so headers must go out with
/// `end_stream=false` and the empty end-stream frame follows.
#[test]
fn continue_and_dont_end_stream_also_reaches_the_terminal() {
    block_on(async {
        let seen = Arc::new(Mutex::new(None));
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(DontEndStreamThenInjectFilter {
            injected: Bytes::new(),
        })];
        let mgr = FilterManager {
            filters,
            ctx: ChainCtx::new(Rc::new(RefCell::new(StreamInfo::default()))),
            terminal: Box::new(EndStreamRecordingTerminal { seen: seen.clone() }),
            buffer_limit: DEFAULT_BUFFER_LIMIT,
        };
        let resp = mgr.run(request(b"")).await;
        assert_eq!(resp.head.status, StatusCode::OK);
        assert_eq!(
            *seen.lock().unwrap(),
            Some(false),
            "the terminal must be told the stream is NOT over either"
        );
    });
}

/// S2.2 (I2): the ENCODE-direction mirror of I1 — `ContinueAndDontEndStream`
/// on `encode_headers`.
///
/// The encode side is NOT symmetric with decode (see `encode_headers_phase`'s
/// doc comment): headers already go out with `end_stream=false`
/// unconditionally, since a streaming body's emptiness can't be known ahead of
/// time. So the status can't mean "forward headers with end_stream=false" —
/// that's already what happens. What it DOES mean here: the claiming filter
/// takes over responsibility for telling positions after it (toward the
/// client) when the response is really over. When `upstream` naturally
/// exhausts, those positions see `end_stream=false` instead of the automatic
/// `true` — the claiming filter must supply the real end itself, via
/// `inject_encoded_data_to_filter_chain(.., end_stream: true)`.
///
/// A filter positioned so it does NOT see it (`RecordsEncodeDataFilter` here
/// is configured BEFORE the claimant, i.e. AFTER it in encode order — see
/// `EncodeState::dont_end_stream_from`'s doc on position vs. config order) so
/// this is a real assertion, not a tautology: without the status,
/// `end_stream` on the natural flush is unconditionally `true`.
struct DontEndStreamThenInjectOnFlushFilter {
    /// Supplied via `inject_encoded_data_to_filter_chain` once this filter
    /// sees the real (unsuppressed, since it's at the claiming position
    /// itself) `end_stream=true` on `encode_data`.
    injected: Bytes,
}

impl HttpFilter for DontEndStreamThenInjectOnFlushFilter {
    fn encode_headers(
        &mut self,
        _cb: &mut dyn EncoderCallbacks,
        _h: &mut ResponseHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        FilterHeadersStatus::ContinueAndDontEndStream
    }

    fn encode_data(
        &mut self,
        cb: &mut dyn EncoderCallbacks,
        _data: &mut Bytes,
        end_stream: bool,
    ) -> FilterDataStatus {
        if end_stream {
            cb.inject_encoded_data_to_filter_chain(self.injected.clone(), true);
        }
        FilterDataStatus::Continue
    }
}

/// Records every `(data, end_stream)` pair a filter's `encode_data` observed
/// — the encode-side counterpart to `ProbeFilter::seen_decode_data`, except
/// `ProbeFilter::seen_encode_data` (S2.5) throws away `end_stream`, which is
/// the one thing this test needs to see.
struct RecordsEncodeDataFilter {
    seen: Arc<Mutex<Vec<(Bytes, bool)>>>,
}

impl HttpFilter for RecordsEncodeDataFilter {
    fn encode_data(
        &mut self,
        _cb: &mut dyn EncoderCallbacks,
        data: &mut Bytes,
        end_stream: bool,
    ) -> FilterDataStatus {
        self.seen.lock().unwrap().push((data.clone(), end_stream));
        FilterDataStatus::Continue
    }
}

#[test]
fn encode_continue_and_dont_end_stream_forwards_headers_with_end_stream_false() {
    block_on(async {
        let seen = Arc::new(Mutex::new(Vec::new()));
        // Config order [recorder, sender] -> encode order visits `sender`
        // FIRST (position 0, closer to upstream) and `recorder` SECOND
        // (position 1, closer to the client) -- S2.1's reverse-config-order
        // rule. `recorder` is therefore genuinely "after" the claimant.
        let filters: Vec<Box<dyn HttpFilter>> = vec![
            Box::new(RecordsEncodeDataFilter { seen: seen.clone() }),
            Box::new(DontEndStreamThenInjectOnFlushFilter {
                injected: Bytes::from_static(b"late tail"),
            }),
        ];
        let (status, _req_seen, resp_body) =
            run_chain(filters, log_of(), b"", DEFAULT_BUFFER_LIMIT).await;
        assert_eq!(status, StatusCode::OK);

        // `run_chain`'s terminal always answers with a single `b"resp"`
        // chunk and no `content-length` header, so the flow is: one real
        // data frame (end_stream=false), then the synthetic end-of-stream
        // flush the claim suppresses, then the injected tail.
        let seen = seen.lock().unwrap();
        assert!(
            seen.contains(&(Bytes::from_static(b"resp"), false)),
            "the real response chunk must still flow through untouched; saw: {seen:?}"
        );
        assert!(
            seen.contains(&(Bytes::new(), false)),
            "the automatic end-of-stream flush must reach the filter after the \
             claimant as end_stream=false, not true -- that's the whole status; \
             saw: {seen:?}"
        );
        assert!(
            seen.contains(&(Bytes::from_static(b"late tail"), true)),
            "the claimant's own injected tail must reach the filter after it \
             as end_stream=true -- it alone gets to assert the real end; \
             saw: {seen:?}"
        );
        assert_eq!(
            resp_body,
            Bytes::from_static(b"resplate tail"),
            "the injected tail must actually reach the wire, appended after \
             the real response body"
        );
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
    let mut ctx = ChainCtx::new(Rc::new(RefCell::new(StreamInfo::default())));
    ctx.decode.current_idx = 2;
    let mut cb = DecoderCallbacksAdapter::new(&mut ctx);
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
    let mut ctx = ChainCtx::new(Rc::new(RefCell::new(StreamInfo::default())));
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

// --- S2.8 (ADR-0004 step 1): the filter manager resolves and caches the
// route, and `DecoderCallbacks::route()`/`clear_route_cache()` are real. ---

/// Build a request identical to [`request`] except for `:path` -- the S2.8
/// tests below need to control which route matches.
fn request_with_path(path: &'static str, body: &'static [u8]) -> HttpRequestParts {
    HttpRequestParts {
        head: RequestHeaders {
            method: Method::POST,
            uri: Uri::from_static(path),
            headers: HeaderMap::new(),
        },
        body: bytes_to_seam_body(Bytes::from_static(body), None),
        downstream: DownstreamInfo::loopback(),
    }
}

/// A route table fixture for the tests below: domain `*` with two routes,
/// distinguished by path prefix, so a filter that rewrites `:path` can be
/// proven to land on a genuinely DIFFERENT route, not just re-match the same
/// one.
fn route_table_two_routes() -> Arc<RouteTable> {
    fn route(name: &str, prefix: &str, cluster: &str) -> Arc<RouteEntry> {
        Arc::new(RouteEntry {
            name: Some(name.to_string()),
            matcher: RouteMatcher {
                path: PathMatch::Prefix(prefix.to_string()),
                case_sensitive: true,
                headers: Vec::new(),
            },
            action: RouteActionIR::Forward(ForwardAction {
                target: ForwardTarget::Cluster(cluster.to_string()),
                timeout: None,
                idle_timeout: None,
                retry_policy: None,
                host_rewrite_literal: None,
                prefix_rewrite: None,
            }),
            request_headers_to_add: Vec::new(),
            typed_per_filter_config: BTreeMap::new(),
            route_index: 0,
        })
    }
    Arc::new(
        RouteTable::new(
            "test-routes".to_string(),
            vec![VirtualHostIR {
                name: "vh".to_string(),
                domains: vec!["*".to_string()],
                routes: vec![
                    route("route-a", "/a", "cluster-a"),
                    route("route-b", "/b", "cluster-b"),
                ],
                typed_per_filter_config: BTreeMap::new(),
            }],
            BTreeMap::new(),
        )
        .expect("two non-overlapping prefixes on one domain is a valid table"),
    )
}

/// S2.8 test filter: calls `cb.route()` some number of times from
/// `decode_headers` (recording each result), optionally rewrites `:path` and
/// calls `clear_route_cache()` at the end of `decode_headers`, and -- if
/// asked -- calls `route()` once more from `decode_data`. The split across
/// two callbacks matters: the manager only re-reads `:authority`/`:path`
/// from the live head immediately before EACH filter callback (see
/// `sync_route_head`'s doc in the parent module), so a mutation this same
/// filter makes to its `headers` parameter only becomes visible to `route()`
/// on the NEXT callback the driver hands it -- `decode_data`, here.
struct RouteProbeFilter {
    seen: Rc<RefCell<Vec<Option<Arc<RouteEntry>>>>>,
    calls_in_headers: usize,
    rewrite_path: Option<&'static str>,
    call_route_in_data: bool,
}

impl HttpFilter for RouteProbeFilter {
    fn decode_headers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        for _ in 0..self.calls_in_headers {
            self.seen.borrow_mut().push(cb.route());
        }
        if let Some(path) = self.rewrite_path {
            headers.uri = Uri::from_static(path);
            cb.clear_route_cache();
        }
        FilterHeadersStatus::Continue
    }

    fn decode_data(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        _data: &mut Bytes,
        _end_stream: bool,
    ) -> FilterDataStatus {
        if self.call_route_in_data {
            self.seen.borrow_mut().push(cb.route());
        }
        FilterDataStatus::Continue
    }
}

/// The headline fix: a decode filter calling `cb.route()` gets the matching
/// `RouteEntry`, not `None`.
#[test]
fn route_resolves_to_the_matching_route_entry() {
    block_on(async {
        let seen = Rc::new(RefCell::new(Vec::new()));
        let filter = RouteProbeFilter {
            seen: seen.clone(),
            calls_in_headers: 1,
            rewrite_path: None,
            call_route_in_data: false,
        };
        let status = run_chain_req_with_route_table(
            vec![Box::new(filter)],
            log_of(),
            request_with_path("/a/chat", b""),
            route_table_two_routes(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let seen = seen.borrow();
        assert_eq!(seen.len(), 1);
        let route = seen[0].as_ref().expect("route() must resolve, not None");
        assert_eq!(route.name.as_deref(), Some("route-a"));
    });
}

/// Resolution happens ONCE across multiple `route()` calls: every call
/// (absent a `clear_route_cache()`) returns the SAME `Arc` allocation.
#[test]
fn route_resolves_only_once_across_repeated_calls() {
    block_on(async {
        let seen = Rc::new(RefCell::new(Vec::new()));
        let filter = RouteProbeFilter {
            seen: seen.clone(),
            calls_in_headers: 3,
            rewrite_path: None,
            call_route_in_data: false,
        };
        let status = run_chain_req_with_route_table(
            vec![Box::new(filter)],
            log_of(),
            request_with_path("/a/chat", b""),
            route_table_two_routes(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let seen = seen.borrow();
        assert_eq!(seen.len(), 3);
        let first = seen[0].as_ref().expect("must resolve");
        for (i, route) in seen.iter().enumerate() {
            let route = route.as_ref().expect("must resolve");
            assert!(
                Arc::ptr_eq(first, route),
                "call #{i} returned a different allocation than call #0 -- \
                 route() re-resolved instead of returning the cached Arc"
            );
        }
    });
}

/// The S2.8 contract that matters most: a filter rewrites `:path` to
/// something matching a DIFFERENT route and calls `clear_route_cache()`; the
/// next `route()` call (on the next callback the driver hands this filter,
/// per `RouteProbeFilter`'s doc) returns that different route, not the
/// stale cached one.
#[test]
fn clear_route_cache_forces_re_resolution_after_a_path_rewrite() {
    block_on(async {
        let seen = Rc::new(RefCell::new(Vec::new()));
        let filter = RouteProbeFilter {
            seen: seen.clone(),
            calls_in_headers: 1,
            rewrite_path: Some("http://example.test/b/chat"),
            call_route_in_data: true,
        };
        let status = run_chain_req_with_route_table(
            vec![Box::new(filter)],
            log_of(),
            request_with_path("/a/chat", b"body"),
            route_table_two_routes(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let seen = seen.borrow();
        assert_eq!(
            seen.len(),
            2,
            "one call from decode_headers, one from decode_data"
        );
        let before = seen[0].as_ref().expect("must resolve before the rewrite");
        let after = seen[1]
            .as_ref()
            .expect("must re-resolve after clear_route_cache(), not stay None");
        assert_eq!(before.name.as_deref(), Some("route-a"));
        assert_eq!(
            after.name.as_deref(),
            Some("route-b"),
            "clear_route_cache() must force re-resolution against the REWRITTEN \
             :path, not replay the stale cached route (S2.8)"
        );
        assert!(
            !Arc::ptr_eq(before, after),
            "before/after must be genuinely different allocations, not the same \
             route re-matched"
        );
    });
}

// --- ADR-0004 step 4 increment 2: resolved `typed_per_filter_config` -------
//
// These tests exercise `build_per_route_table` (the HCM-build-time
// resolution + validation) and `DecoderCallbacks::per_route_config` (the
// runtime read) directly, following this file's existing convention of
// driving `FilterManager`/`ChainCtx` by hand rather than through
// `FilterChainHandler`.

/// A `google.protobuf.StringValue`-shaped `DynamicMessage` carrying `tag` in
/// its `value` field. `google.protobuf.StringValue` is a well-known type
/// already bundled in `prost_reflect`'s global descriptor pool (see
/// `DescriptorPool::global`'s doc), so this needs no `proxy-api` Envoy
/// descriptors -- any real message shape would do, since only `TagFactory`
/// below ever reads it, and only to recover `tag`.
fn string_value(tag: &str) -> prost_reflect::DynamicMessage {
    let desc = prost_reflect::DescriptorPool::global()
        .get_message_by_name("google.protobuf.StringValue")
        .expect("google.protobuf.StringValue is a well-known type");
    let mut msg = prost_reflect::DynamicMessage::new(desc);
    msg.set_field_by_name("value", prost_reflect::Value::String(tag.to_string()));
    msg
}

/// A `typed_per_filter_config` entry carrying `tag` (see [`string_value`]).
fn tag_override(tag: &str) -> PerFilterConfig {
    PerFilterConfig {
        type_url: "type.googleapis.com/google.protobuf.StringValue".to_string(),
        config: Some(string_value(tag)),
        is_optional: false,
        disabled: false,
    }
}

/// A resolved per-route override that just carries an identifying tag --
/// [`tag_of`] downcasts an `Arc<dyn PerRouteConfig>` back to this so a test
/// can tell WHICH override resolved.
#[derive(Debug, PartialEq, Eq)]
struct TagConfig(String);

impl PerRouteConfig for TagConfig {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Downcast whatever `per_route_config()` returned back to its tag, if any.
fn tag_of(cfg: Option<Arc<dyn PerRouteConfig>>) -> Option<String> {
    cfg.and_then(|c| c.as_any().downcast_ref::<TagConfig>().map(|t| t.0.clone()))
}

/// An `HttpFilterFactory` fixture whose `parse_per_route` reads the
/// `google.protobuf.StringValue.value` field [`tag_override`] wrote and
/// hands back a [`TagConfig`] carrying it. `create()` is never exercised by
/// these tests (none of them build a real per-stream instance from this
/// factory), so it just fails loudly if that ever changes.
struct TagFactory;

impl HttpFilterFactory for TagFactory {
    fn type_url(&self) -> &'static str {
        "type.llmproxy.dev/test.TagFilter"
    }

    fn create(
        &self,
        _config: &prost_reflect::DynamicMessage,
        _ctx: &FactoryContext,
    ) -> Result<Box<dyn FilterInstanceFactory>, ConfigError> {
        panic!("TagFactory::create is not exercised by the per-route-config tests")
    }

    fn parse_per_route(
        &self,
        config: &prost_reflect::DynamicMessage,
    ) -> Result<Arc<dyn PerRouteConfig>, ConfigError> {
        let tag = config
            .get_field_by_name("value")
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        Ok(Arc::new(TagConfig(tag)))
    }
}

/// An `HttpFilterFactory` fixture that DOES support per-route config but
/// rejects every config it is handed. This is the other side of
/// [`NoPerRouteFactory`]: "I don't do per-route config" (the trait default,
/// an `Unimplemented`) versus "I do, and yours is wrong" (a validation
/// error). `is_optional` must tolerate only the first.
struct RejectingPerRouteFactory;

impl HttpFilterFactory for RejectingPerRouteFactory {
    fn type_url(&self) -> &'static str {
        "type.llmproxy.dev/test.RejectingFilter"
    }

    fn create(
        &self,
        _config: &prost_reflect::DynamicMessage,
        _ctx: &FactoryContext,
    ) -> Result<Box<dyn FilterInstanceFactory>, ConfigError> {
        panic!("RejectingPerRouteFactory::create is not exercised by the per-route-config tests")
    }

    fn parse_per_route(
        &self,
        _config: &prost_reflect::DynamicMessage,
    ) -> Result<Arc<dyn PerRouteConfig>, ConfigError> {
        Err(ConfigError::InvalidValue {
            field_path: "test.RejectingFilter".to_string(),
            reason: "this per-route config is malformed".to_string(),
        })
    }
}

/// An `HttpFilterFactory` fixture that never overrides `parse_per_route` --
/// exercises the trait's own default ("this filter has no per-route
/// config").
struct NoPerRouteFactory;

impl HttpFilterFactory for NoPerRouteFactory {
    fn type_url(&self) -> &'static str {
        "type.llmproxy.dev/test.NoPerRouteFilter"
    }

    fn create(
        &self,
        _config: &prost_reflect::DynamicMessage,
        _ctx: &FactoryContext,
    ) -> Result<Box<dyn FilterInstanceFactory>, ConfigError> {
        panic!("NoPerRouteFactory::create is not exercised by the per-route-config tests")
    }
}

/// A route table with a single route matching everything, carrying
/// `route_config_overrides`/`vhost_overrides`/`route_overrides` at their
/// respective levels -- for the build-time validation tests and the
/// "most specific wins" test, which need all three levels configurable
/// independently.
fn route_table_with_all_levels(
    route_config_overrides: BTreeMap<String, PerFilterConfig>,
    vhost_overrides: BTreeMap<String, PerFilterConfig>,
    route_overrides: BTreeMap<String, PerFilterConfig>,
) -> Arc<RouteTable> {
    let route = Arc::new(RouteEntry {
        name: Some("only-route".to_string()),
        matcher: RouteMatcher {
            path: PathMatch::Prefix("/".to_string()),
            case_sensitive: true,
            headers: Vec::new(),
        },
        action: RouteActionIR::Forward(ForwardAction {
            target: ForwardTarget::Cluster("cluster-a".to_string()),
            timeout: None,
            idle_timeout: None,
            retry_policy: None,
            host_rewrite_literal: None,
            prefix_rewrite: None,
        }),
        request_headers_to_add: Vec::new(),
        typed_per_filter_config: route_overrides,
        route_index: 0,
    });
    Arc::new(
        RouteTable::new(
            "test-routes".to_string(),
            vec![VirtualHostIR {
                name: "vh".to_string(),
                domains: vec!["*".to_string()],
                routes: vec![route],
                typed_per_filter_config: vhost_overrides,
            }],
            route_config_overrides,
        )
        .expect("single catch-all route is valid"),
    )
}

/// Like [`run_chain_req_with_route_table`], but also attaches a resolved
/// [`PerRouteTable`] (built by [`build_per_route_table`]) to `ctx`, for the
/// `per_route_config()` tests below.
async fn run_chain_req_with_route_and_per_route(
    filters: Vec<Box<dyn HttpFilter>>,
    log: Log,
    req: HttpRequestParts,
    route_table: Arc<RouteTable>,
    per_route: PerRouteTable,
) -> StatusCode {
    let seen_body = Arc::new(Mutex::new(Bytes::new()));
    let terminal = RecordingTerminal {
        log,
        term_log: None,
        seen_body,
        seen_request_id: Arc::new(Mutex::new(None)),
        seen_headers: None,
        captured_body: Bytes::new(),
    };
    let mgr = FilterManager {
        filters,
        ctx: ChainCtx::new(Rc::new(RefCell::new(StreamInfo::default())))
            .with_route_table(route_table)
            .with_per_route(Arc::new(per_route)),
        terminal: Box::new(terminal),
        buffer_limit: DEFAULT_BUFFER_LIMIT,
    };
    let resp = mgr.run(req).await;
    let status = resp.head.status;
    let _ = resp.body.collect().await;
    status
}

/// A probe filter that records what `per_route_config()` returned (as its
/// tag, or `None`) from `decode_headers` -- and, if `check_on_encode` is
/// set, again from `encode_headers` (proving `EncoderCallbacksAdapter`'s
/// position -> filter-index mapping is correct too).
struct PerRouteProbeFilter {
    seen: Rc<RefCell<Vec<Option<String>>>>,
    check_on_encode: bool,
}

impl HttpFilter for PerRouteProbeFilter {
    fn decode_headers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        _headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        self.seen.borrow_mut().push(tag_of(cb.per_route_config()));
        FilterHeadersStatus::Continue
    }

    fn encode_headers(
        &mut self,
        cb: &mut dyn EncoderCallbacks,
        _headers: &mut ResponseHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        if self.check_on_encode {
            self.seen.borrow_mut().push(tag_of(cb.per_route_config()));
        }
        FilterHeadersStatus::Continue
    }
}

/// Item 1: a filter reads its own route-level override.
#[test]
fn per_route_config_reads_the_calling_filters_own_route_level_override() {
    block_on(async {
        let seen = Rc::new(RefCell::new(Vec::new()));
        let filter = PerRouteProbeFilter {
            seen: seen.clone(),
            check_on_encode: false,
        };
        let mut route_overrides = BTreeMap::new();
        route_overrides.insert("filter-a".to_string(), tag_override("route-tag"));
        let route_table =
            route_table_with_all_levels(BTreeMap::new(), BTreeMap::new(), route_overrides);
        let names = vec!["filter-a".to_string()];
        let factories: Vec<Arc<dyn HttpFilterFactory>> = vec![Arc::new(TagFactory)];
        let per_route =
            build_per_route_table(&names, &factories, &route_table).expect("valid overrides");

        let status = run_chain_req_with_route_and_per_route(
            vec![Box::new(filter)],
            log_of(),
            request_with_path("/x", b""),
            route_table,
            per_route,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(seen.borrow().as_slice(), [Some("route-tag".to_string())]);
    });
}

/// Item 2: route beats virtual-host beats route-configuration, all three
/// configured at once for the same filter.
#[test]
fn per_route_config_most_specific_level_wins() {
    block_on(async {
        let seen = Rc::new(RefCell::new(Vec::new()));
        let filter = PerRouteProbeFilter {
            seen: seen.clone(),
            check_on_encode: false,
        };
        let mut route_config_overrides = BTreeMap::new();
        route_config_overrides.insert("filter-a".to_string(), tag_override("route-config-tag"));
        let mut vhost_overrides = BTreeMap::new();
        vhost_overrides.insert("filter-a".to_string(), tag_override("vhost-tag"));
        let mut route_overrides = BTreeMap::new();
        route_overrides.insert("filter-a".to_string(), tag_override("route-tag"));
        let route_table =
            route_table_with_all_levels(route_config_overrides, vhost_overrides, route_overrides);
        let names = vec!["filter-a".to_string()];
        let factories: Vec<Arc<dyn HttpFilterFactory>> = vec![Arc::new(TagFactory)];
        let per_route =
            build_per_route_table(&names, &factories, &route_table).expect("valid overrides");

        let status = run_chain_req_with_route_and_per_route(
            vec![Box::new(filter)],
            log_of(),
            request_with_path("/x", b""),
            route_table,
            per_route,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            seen.borrow().as_slice(),
            [Some("route-tag".to_string())],
            "the route-level entry must win over both the virtual-host and \
             route-configuration entries"
        );
    });
}

/// Item 3: a filter with no override gets `None`, while a sibling filter on
/// the SAME route gets `Some` -- proves indexing is per-filter, not
/// per-route.
#[test]
fn per_route_config_is_isolated_per_filter() {
    block_on(async {
        let seen_a = Rc::new(RefCell::new(Vec::new()));
        let seen_b = Rc::new(RefCell::new(Vec::new()));
        let filter_a = PerRouteProbeFilter {
            seen: seen_a.clone(),
            check_on_encode: false,
        };
        let filter_b = PerRouteProbeFilter {
            seen: seen_b.clone(),
            check_on_encode: false,
        };
        let mut route_overrides = BTreeMap::new();
        route_overrides.insert("filter-a".to_string(), tag_override("route-tag"));
        let route_table =
            route_table_with_all_levels(BTreeMap::new(), BTreeMap::new(), route_overrides);
        let names = vec!["filter-a".to_string(), "filter-b".to_string()];
        let factories: Vec<Arc<dyn HttpFilterFactory>> =
            vec![Arc::new(TagFactory), Arc::new(TagFactory)];
        let per_route =
            build_per_route_table(&names, &factories, &route_table).expect("valid overrides");

        let status = run_chain_req_with_route_and_per_route(
            vec![Box::new(filter_a), Box::new(filter_b)],
            log_of(),
            request_with_path("/x", b""),
            route_table,
            per_route,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(seen_a.borrow().as_slice(), [Some("route-tag".to_string())]);
        assert_eq!(
            seen_b.borrow().as_slice(),
            [None],
            "filter-b has no override anywhere -- it must see None, not filter-a's"
        );
    });
}

/// Item 4: an entry naming a filter absent from the chain is a build error;
/// `is_optional: true` on the same entry builds clean.
#[test]
fn per_route_config_absent_filter_is_a_build_error_unless_optional() {
    let names = vec!["configured-filter".to_string()];
    let factories: Vec<Arc<dyn HttpFilterFactory>> = vec![Arc::new(TagFactory)];

    let mut overrides = BTreeMap::new();
    overrides.insert(
        "not-in-chain".to_string(),
        PerFilterConfig {
            type_url: String::new(),
            config: None,
            is_optional: false,
            disabled: false,
        },
    );
    let route_table = route_table_with_all_levels(BTreeMap::new(), BTreeMap::new(), overrides);
    let err = build_per_route_table(&names, &factories, &route_table)
        .expect_err("a filter name absent from the chain must fail the build");
    assert!(
        matches!(err, ConfigError::Validation { .. }),
        "expected Validation, got {err:?}"
    );

    let mut overrides = BTreeMap::new();
    overrides.insert(
        "not-in-chain".to_string(),
        PerFilterConfig {
            type_url: String::new(),
            config: None,
            is_optional: true,
            disabled: false,
        },
    );
    let route_table = route_table_with_all_levels(BTreeMap::new(), BTreeMap::new(), overrides);
    build_per_route_table(&names, &factories, &route_table)
        .expect("is_optional must make an absent filter name build clean");
}

/// Item 5: an entry for a filter whose factory has no `parse_per_route`
/// support is a build error; `is_optional: true` builds clean.
#[test]
fn per_route_config_unsupported_filter_is_a_build_error_unless_optional() {
    let names = vec!["configured-filter".to_string()];
    let factories: Vec<Arc<dyn HttpFilterFactory>> = vec![Arc::new(NoPerRouteFactory)];

    let mut overrides = BTreeMap::new();
    overrides.insert("configured-filter".to_string(), tag_override("irrelevant"));
    let route_table = route_table_with_all_levels(BTreeMap::new(), BTreeMap::new(), overrides);
    let err = build_per_route_table(&names, &factories, &route_table)
        .expect_err("a filter with no per-route support must fail the build");
    assert!(
        matches!(err, ConfigError::Unimplemented { .. }),
        "expected Unimplemented (the trait's own default), got {err:?}"
    );

    let mut optional_overrides = BTreeMap::new();
    optional_overrides.insert(
        "configured-filter".to_string(),
        PerFilterConfig {
            is_optional: true,
            ..tag_override("irrelevant")
        },
    );
    let route_table =
        route_table_with_all_levels(BTreeMap::new(), BTreeMap::new(), optional_overrides);
    build_per_route_table(&names, &factories, &route_table)
        .expect("is_optional must tolerate a filter with no per-route support");
}

/// `is_optional` means "ignore this if the filter does not SUPPORT per-route
/// config" -- NOT "ignore any error". A filter that supports per-route config
/// and rejects the one it was given must still fail the build, or a typo'd
/// override on an optional entry would be silently dropped on a filter that
/// would have honored a correct one (ground rule #1).
#[test]
fn is_optional_does_not_swallow_a_supported_filters_rejection() {
    let names = vec!["configured-filter".to_string()];
    let factories: Vec<Arc<dyn HttpFilterFactory>> = vec![Arc::new(RejectingPerRouteFactory)];

    let mut overrides = BTreeMap::new();
    overrides.insert(
        "configured-filter".to_string(),
        PerFilterConfig {
            is_optional: true,
            ..tag_override("malformed")
        },
    );
    let route_table = route_table_with_all_levels(BTreeMap::new(), BTreeMap::new(), overrides);

    let err = build_per_route_table(&names, &factories, &route_table).expect_err(
        "is_optional must NOT swallow a rejection from a filter that does support \
         per-route config -- only the trait default's Unimplemented",
    );
    assert!(
        matches!(err, ConfigError::InvalidValue { .. }),
        "expected the filter's own InvalidValue to propagate, got {err:?}"
    );
}

/// Item 6: `disabled: true` is a build error mentioning that it is not yet
/// implemented.
#[test]
fn per_route_config_disabled_is_a_build_error_mentioning_not_implemented() {
    let names = vec!["configured-filter".to_string()];
    let factories: Vec<Arc<dyn HttpFilterFactory>> = vec![Arc::new(TagFactory)];

    let mut overrides = BTreeMap::new();
    overrides.insert(
        "configured-filter".to_string(),
        PerFilterConfig {
            type_url: String::new(),
            config: None,
            is_optional: false,
            disabled: true,
        },
    );
    let route_table = route_table_with_all_levels(BTreeMap::new(), BTreeMap::new(), overrides);
    let err = build_per_route_table(&names, &factories, &route_table)
        .expect_err("disabled must fail the build (not yet implemented)");
    match err {
        ConfigError::Unimplemented { reason, .. } => assert!(
            reason.contains("not yet implemented") || reason.contains("not implemented"),
            "reason should say disabling a filter per-route isn't implemented yet: {reason}"
        ),
        other => panic!("expected Unimplemented, got {other:?}"),
    }
}

/// Like [`RouteProbeFilter`], but calls `per_route_config()` instead of
/// `route()` -- item 7: after a path rewrite + `clear_route_cache()`, the
/// NEXT `per_route_config()` call must reflect the rewritten route's
/// override, not the stale cached one. Modeled directly on
/// `clear_route_cache_forces_re_resolution_after_a_path_rewrite`.
struct PerRouteRewriteProbeFilter {
    seen: Rc<RefCell<Vec<Option<String>>>>,
    rewrite_path: &'static str,
}

impl HttpFilter for PerRouteRewriteProbeFilter {
    fn decode_headers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        self.seen.borrow_mut().push(tag_of(cb.per_route_config()));
        headers.uri = Uri::from_static(self.rewrite_path);
        cb.clear_route_cache();
        FilterHeadersStatus::Continue
    }

    fn decode_data(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        _data: &mut Bytes,
        _end_stream: bool,
    ) -> FilterDataStatus {
        self.seen.borrow_mut().push(tag_of(cb.per_route_config()));
        FilterDataStatus::Continue
    }
}

/// A two-route table (mirrors [`route_table_two_routes`]), each route
/// carrying its OWN route-level override for the same filter name, so a
/// rewrite from one route to the other is observable through
/// `per_route_config()`, not just `route()`.
fn route_table_two_routes_with_tags() -> (
    Arc<RouteTable>,
    Vec<String>,
    Vec<Arc<dyn HttpFilterFactory>>,
) {
    fn route(name: &str, prefix: &str, cluster: &str, tag: &str) -> Arc<RouteEntry> {
        let mut overrides = BTreeMap::new();
        overrides.insert("filter-a".to_string(), tag_override(tag));
        Arc::new(RouteEntry {
            name: Some(name.to_string()),
            matcher: RouteMatcher {
                path: PathMatch::Prefix(prefix.to_string()),
                case_sensitive: true,
                headers: Vec::new(),
            },
            action: RouteActionIR::Forward(ForwardAction {
                target: ForwardTarget::Cluster(cluster.to_string()),
                timeout: None,
                idle_timeout: None,
                retry_policy: None,
                host_rewrite_literal: None,
                prefix_rewrite: None,
            }),
            request_headers_to_add: Vec::new(),
            typed_per_filter_config: overrides,
            route_index: 0,
        })
    }
    let route_table = Arc::new(
        RouteTable::new(
            "test-routes".to_string(),
            vec![VirtualHostIR {
                name: "vh".to_string(),
                domains: vec!["*".to_string()],
                routes: vec![
                    route("route-a", "/a", "cluster-a", "route-a-tag"),
                    route("route-b", "/b", "cluster-b", "route-b-tag"),
                ],
                typed_per_filter_config: BTreeMap::new(),
            }],
            BTreeMap::new(),
        )
        .expect("two non-overlapping prefixes on one domain is a valid table"),
    );
    let names = vec!["filter-a".to_string()];
    let factories: Vec<Arc<dyn HttpFilterFactory>> = vec![Arc::new(TagFactory)];
    (route_table, names, factories)
}

/// Item 7.
#[test]
fn per_route_config_reflects_the_new_route_after_clear_route_cache() {
    block_on(async {
        let seen = Rc::new(RefCell::new(Vec::new()));
        let filter = PerRouteRewriteProbeFilter {
            seen: seen.clone(),
            rewrite_path: "http://example.test/b/chat",
        };
        let (route_table, names, factories) = route_table_two_routes_with_tags();
        let per_route =
            build_per_route_table(&names, &factories, &route_table).expect("valid overrides");

        let status = run_chain_req_with_route_and_per_route(
            vec![Box::new(filter)],
            log_of(),
            request_with_path("/a/chat", b"body"),
            route_table,
            per_route,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let seen = seen.borrow();
        assert_eq!(
            seen.len(),
            2,
            "one call from decode_headers, one from decode_data"
        );
        assert_eq!(seen[0], Some("route-a-tag".to_string()));
        assert_eq!(
            seen[1],
            Some("route-b-tag".to_string()),
            "clear_route_cache() must force per_route_config() to resolve against \
             the REWRITTEN route too, not replay the stale cached one"
        );
    });
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
        let seen_request_id = Arc::new(Mutex::new(None));
        let terminal_factory: Arc<dyn TerminalFilterInstanceFactory> =
            Arc::new(RecordingTerminalFactory {
                seen_body: Arc::new(Mutex::new(Bytes::new())),
                seen_request_id: seen_request_id.clone(),
                seen_headers: None,
                term_log: None,
            });
        let handler = FilterChainHandler::new(
            Vec::new(),
            terminal_factory,
            empty_route_table(),
            generate_request_id,
            false,
            0,
        );

        let mut req = request(b"hi");
        if let Some(id) = existing_request_id {
            req.head.headers.insert(
                HeaderName::from_static("x-request-id"),
                HeaderValue::from_static(id),
            );
        }
        let _ = handler.handle(req).await;
        let seen = seen_request_id.lock().unwrap().clone();
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
        let seen_headers = Arc::new(Mutex::new(None));
        let terminal_factory: Arc<dyn TerminalFilterInstanceFactory> =
            Arc::new(RecordingTerminalFactory {
                seen_body: Arc::new(Mutex::new(Bytes::new())),
                seen_request_id: Arc::new(Mutex::new(None)),
                seen_headers: Some(seen_headers.clone()),
                term_log: None,
            });
        let handler = FilterChainHandler::new(
            Vec::new(),
            terminal_factory,
            empty_route_table(),
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
            .lock()
            .unwrap()
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

// --- Access logging relocation (moved from `RouterHandler` to
// `FilterChainHandler`) -----------------------------------------------------
//
// These two tests ARE the acceptance criteria for that move (see the task
// this shipped under): first, that the reordering fix is real -- an encode
// filter's own end-of-stream write reaches the rendered log line, which it
// cannot if `LoggingBody` is nested INSIDE the encode chain the way the
// pre-relocation design had it. Second, that a filter-chain local reply --
// which never reaches the router terminal at all -- is now logged, which it
// never was before (there was nothing above the router to log it with).
//
// Both drive real requests through `FilterChainHandler::handle` (not
// `FilterManager` directly, like the rest of this file) with a real file
// sink, mirroring `proxy-http/tests/router_access_log.rs`'s style, since the
// whole point is to observe the wrap `FilterChainHandler::handle` itself
// does after `FilterManager::run` returns.

/// An encode filter that stamps `StreamInfo::llm.usage` only on the
/// end-of-stream `encode_data` callback -- mirrors what the real WP-33/34
/// usage filter does once it has observed the whole streamed response. If
/// `LoggingBody` were still nested INSIDE the encode chain (the bug this
/// relocation fixes), it would already have rendered its line before this
/// callback ever ran, and the log would show `-`, not a real value.
struct StampsUsageOnEndStreamFilter;

impl HttpFilter for StampsUsageOnEndStreamFilter {
    fn encode_data(
        &mut self,
        cb: &mut dyn EncoderCallbacks,
        _data: &mut Bytes,
        end_stream: bool,
    ) -> FilterDataStatus {
        if end_stream {
            cb.stream_info().llm.usage = Some(crate::stream_info::LlmTokenUsage {
                input_tokens: 42,
                cached_tokens: 0,
                cache_creation_tokens: 0,
                output_tokens: 0,
            });
        }
        FilterDataStatus::Continue
    }
}

struct StampsUsageOnEndStreamFilterFactory;

impl FilterInstanceFactory for StampsUsageOnEndStreamFilterFactory {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(StampsUsageOnEndStreamFilter)
    }
}

/// A decode filter that unconditionally rejects the request via
/// `send_local_reply` -- standing in for e.g. an auth filter -- so its
/// response never reaches the router terminal at all.
struct LocalReplyFilter;

impl HttpFilter for LocalReplyFilter {
    fn decode_headers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        _headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        cb.send_local_reply(
            StatusCode::FORBIDDEN,
            "denied by filter",
            None,
            "test_local_reply",
        );
        FilterHeadersStatus::StopIteration
    }
}

struct LocalReplyFilterFactory;

impl FilterInstanceFactory for LocalReplyFilterFactory {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(LocalReplyFilter)
    }
}

/// A unique temp-file path, same technique as
/// `proxy-http/tests/router_access_log.rs`'s `temp_path`.
fn temp_log_path(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "proxy-http-filter-manager-access-log-test-{}-{name}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    p
}

fn read_log(path: &std::path::Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

fn text_access_log(path: &std::path::Path, format: &str) -> AccessLogIR {
    AccessLogIR {
        sink: AccessLogSink::File {
            path: path.to_string_lossy().into_owned(),
        },
        format: AccessLogFormat::Text(parse_format(format).unwrap()),
        filter: None,
    }
}

/// The ordering-fix test: without the `FilterChainHandler`-level relocation,
/// `LoggingBody` would be nested inside the encode chain (wrapping the
/// router's own response, the pre-relocation design), so it would render
/// before `StampsUsageOnEndStreamFilter`'s `encode_data` end-of-stream
/// callback ever ran, and `%LLM_INPUT_TOKENS%` would log `-`. This must fail
/// if `LoggingBody` moves back inside the encode chain.
#[test]
fn encode_filters_end_of_stream_write_reaches_the_access_log_line() {
    block_on(async {
        let terminal_factory: Arc<dyn TerminalFilterInstanceFactory> =
            Arc::new(RecordingTerminalFactory {
                seen_body: Arc::new(Mutex::new(Bytes::new())),
                seen_request_id: Arc::new(Mutex::new(None)),
                seen_headers: None,
                term_log: None,
            });
        let path = temp_log_path("ordering");
        let handler = FilterChainHandler::new_with_access_logs(
            vec![Arc::new(StampsUsageOnEndStreamFilterFactory)],
            terminal_factory,
            empty_route_table(),
            false,
            false,
            0,
            &[text_access_log(&path, "%LLM_INPUT_TOKENS%\n")],
        )
        .expect("temp file sink always opens cleanly");

        let resp = handler.handle(request(b"hi")).await;
        assert_eq!(resp.head.status, StatusCode::OK);
        resp.body.collect().await.expect("resp body must collect");

        assert_eq!(
            read_log(&path).trim(),
            "42",
            "the usage the encode filter wrote at end-of-stream must reach the \
             rendered access-log line -- proves `LoggingBody` wraps OUTSIDE the \
             encode chain, not nested inside the router's own response"
        );

        std::fs::remove_file(&path).ok();
    });
}

/// The local-reply test: a decode filter's `send_local_reply` response never
/// reaches `RouterHandler` (the terminal), so before this relocation there
/// was nothing to render a line for it at all. This must fail if the
/// `LoggingBody` wrap moves back to wherever it can only see responses that
/// reached the router terminal.
#[test]
fn a_filter_chain_local_reply_still_produces_an_access_log_line() {
    block_on(async {
        let term_log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let terminal_factory: Arc<dyn TerminalFilterInstanceFactory> =
            Arc::new(RecordingTerminalFactory {
                seen_body: Arc::new(Mutex::new(Bytes::new())),
                seen_request_id: Arc::new(Mutex::new(None)),
                seen_headers: None,
                term_log: Some(term_log.clone()),
            });
        let path = temp_log_path("local-reply");
        let handler = FilterChainHandler::new_with_access_logs(
            vec![Arc::new(LocalReplyFilterFactory)],
            terminal_factory,
            empty_route_table(),
            false,
            false,
            0,
            &[text_access_log(&path, "%RESPONSE_CODE%\n")],
        )
        .expect("temp file sink always opens cleanly");

        let resp = handler.handle(request(b"hi")).await;
        assert_eq!(resp.head.status, StatusCode::FORBIDDEN);
        resp.body.collect().await.expect("resp body must collect");

        assert!(
            term_log
                .lock()
                .unwrap()
                .iter()
                .all(|entry| entry != "terminal"),
            "a filter-chain local reply must never reach the router terminal"
        );
        assert_eq!(
            read_log(&path).trim(),
            "403",
            "a local reply synthesized by the filter chain itself -- which never \
             reaches the router terminal -- must still produce an access-log \
             line; it never did before this relocation"
        );

        std::fs::remove_file(&path).ok();
    });
}

// --- ADR-0004 step 2: async decode filters (`poll_pending`) ----------------

/// A decode filter that returns `StopIteration` from `decode_headers` on its
/// first invocation and offers a `poll_pending` future (one `yield_now`) that
/// the driver must await before re-invoking `decode_headers` on this same
/// filter — at which point it sets `ran` and returns `Continue`. `calls`
/// tracks how many times `decode_headers` actually fired, so a test can
/// assert the resumption really re-invoked the callback rather than the
/// driver inventing progress on its own.
struct AsyncPauseFilter {
    log: Log,
    name: &'static str,
    calls: Rc<RefCell<u32>>,
    ran: Rc<RefCell<bool>>,
    /// If set, applied to the request headers on the SECOND `decode_headers`
    /// call (i.e. "mutation the filter makes once its async work is done" —
    /// per `HttpFilter::poll_pending`'s contract, the future itself can't
    /// touch callbacks/headers, only the next synchronous callback can).
    mutate_on_resume: Option<(&'static str, &'static str)>,
}

impl HttpFilter for AsyncPauseFilter {
    fn decode_headers(
        &mut self,
        _cb: &mut dyn DecoderCallbacks,
        headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        let mut calls = self.calls.borrow_mut();
        *calls += 1;
        self.log
            .borrow_mut()
            .push(format!("{}:decode_headers#{calls}", self.name));
        if *calls == 1 {
            FilterHeadersStatus::StopIteration
        } else {
            if let Some((name, value)) = self.mutate_on_resume {
                headers.headers.insert(
                    HeaderName::from_bytes(name.as_bytes()).expect("valid header name"),
                    HeaderValue::from_str(value).expect("valid header value"),
                );
            }
            FilterHeadersStatus::Continue
        }
    }

    fn poll_pending<'a>(&'a mut self) -> Option<Pin<Box<dyn Future<Output = ()> + 'a>>> {
        // Only the first `decode_headers` call (the one that returned
        // `StopIteration`) has async work; the second returns `Continue`, so
        // the driver never asks again.
        if *self.calls.borrow() == 1 {
            let ran = self.ran.clone();
            Some(Box::pin(async move {
                tokio::task::yield_now().await;
                *ran.borrow_mut() = true;
            }))
        } else {
            None
        }
    }
}

/// Test 1 (headline capability): a decode filter pauses on `decode_headers`,
/// does async work via `poll_pending`, sets a flag, and on resumption returns
/// `Continue` — the request reaches the terminal, and the async work
/// demonstrably ran.
#[test]
fn async_decode_filter_pauses_does_async_work_and_resumes_the_chain() {
    block_on(async {
        let log = log_of();
        let calls = Rc::new(RefCell::new(0));
        let ran = Rc::new(RefCell::new(false));
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(AsyncPauseFilter {
            log: log.clone(),
            name: "a",
            calls: calls.clone(),
            ran: ran.clone(),
            mutate_on_resume: None,
        })];
        let (status, seen_body, _) =
            run_chain(filters, log.clone(), b"hi", DEFAULT_BUFFER_LIMIT).await;

        assert_eq!(
            status,
            StatusCode::OK,
            "the request must reach the terminal"
        );
        assert_eq!(seen_body, Bytes::from_static(b"hi"));
        assert!(
            *ran.borrow(),
            "poll_pending's future must have been awaited by the driver"
        );
        assert_eq!(
            *calls.borrow(),
            2,
            "decode_headers must be re-invoked on the same filter after the \
             async resumption, not skipped over"
        );
        assert!(
            log.borrow().contains(&"terminal".to_string()),
            "log: {:?}",
            log.borrow()
        );
    });
}

/// Test 2: an async decode filter's header mutation (applied when it's
/// re-invoked after its async phase) is visible to the NEXT filter in the
/// chain.
#[test]
fn async_decode_filter_header_mutation_is_visible_to_the_next_filter() {
    block_on(async {
        let log = log_of();
        let calls = Rc::new(RefCell::new(0));
        let ran = Rc::new(RefCell::new(false));
        let seen_by_b = Rc::new(RefCell::new(None));
        let mut b = ProbeFilter::new("b", log.clone());
        b.seen_decode_headers = Some(seen_by_b.clone());
        let filters: Vec<Box<dyn HttpFilter>> = vec![
            Box::new(AsyncPauseFilter {
                log: log.clone(),
                name: "a",
                calls: calls.clone(),
                ran: ran.clone(),
                mutate_on_resume: Some(("x-async-set", "yes")),
            }),
            Box::new(b),
        ];
        let (status, _, _) = run_chain(filters, log.clone(), b"hi", DEFAULT_BUFFER_LIMIT).await;

        assert_eq!(status, StatusCode::OK);
        assert!(*ran.borrow());
        let seen = seen_by_b.borrow().clone().expect("b must have run");
        assert_eq!(
            seen.get("x-async-set").map(|v| v.to_str().unwrap()),
            Some("yes"),
            "the header `a` set on resumption must be visible to `b`, the next \
             filter in the chain"
        );
    });
}

/// Test 3 (no regression): a filter returning `StopIteration` with the
/// default `poll_pending` (`None`) behaves exactly as before this change —
/// `decode_headers` fires exactly once, the buffered data still resolves the
/// hold, and the request still reaches the terminal.
#[test]
fn stop_iteration_with_default_poll_pending_is_unchanged() {
    block_on(async {
        let log = log_of();
        let mut a = ProbeFilter::new("a", log.clone());
        a.decode_headers_status = FilterHeadersStatus::StopIteration;
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(a)];
        let (status, seen_body, _) =
            run_chain(filters, log.clone(), b"hi", DEFAULT_BUFFER_LIMIT).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(seen_body, Bytes::from_static(b"hi"));
        let entries = log.borrow().clone();
        let decode_headers_calls = entries
            .iter()
            .filter(|e| e.as_str() == "a:decode_headers")
            .count();
        assert_eq!(
            decode_headers_calls, 1,
            "the default (no async work) `poll_pending` must not cause an \
             extra `decode_headers` invocation; log: {entries:?}"
        );
    });
}

/// A decode filter that ALWAYS reports async work pending, and always stops
/// again once resumed — the runaway case ADR-0004 step 2 must guard against.
struct AlwaysPendingFilter {
    resumptions: Rc<RefCell<u32>>,
}

impl HttpFilter for AlwaysPendingFilter {
    fn decode_headers(
        &mut self,
        _cb: &mut dyn DecoderCallbacks,
        _headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        FilterHeadersStatus::StopIteration
    }

    fn poll_pending<'a>(&'a mut self) -> Option<Pin<Box<dyn Future<Output = ()> + 'a>>> {
        let resumptions = self.resumptions.clone();
        Some(Box::pin(async move {
            tokio::task::yield_now().await;
            *resumptions.borrow_mut() += 1;
        }))
    }
}

/// Test 4: a filter whose `poll_pending` always returns `Some` must not spin
/// the chain forever — the driver's resumption budget must fail closed with a
/// local reply instead. Bounded by an outer `tokio::time::timeout` so a
/// regression that DOES hang fails this test instead of wedging CI.
#[test]
fn a_filter_that_always_reports_pending_work_fails_closed_instead_of_hanging() {
    block_on(async {
        let resumptions = Rc::new(RefCell::new(0u32));
        let filters: Vec<Box<dyn HttpFilter>> = vec![Box::new(AlwaysPendingFilter {
            resumptions: resumptions.clone(),
        })];
        let log = log_of();

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            run_chain(filters, log.clone(), b"hi", DEFAULT_BUFFER_LIMIT),
        )
        .await
        .expect("must not hang: the resumption budget must terminate the chain");

        let (status, _, _) = result;
        assert!(
            status.is_server_error(),
            "a runaway async filter must fail closed with a local reply, not \
             hang or silently succeed; got {status}"
        );
        assert!(
            *resumptions.borrow() > 0,
            "the filter must actually have been given async resumptions \
             before the budget cut it off"
        );
        assert!(
            !log.borrow().contains(&"terminal".to_string()),
            "a runaway filter must never let the request reach the terminal"
        );
    });
}

// --- WP-45 increment 2a: `DecoderCallbacks::modify_decoded_headers` --------
//
// The motivating bug: a decode filter that splices bytes into the request
// body (WP-45's actual body-rewrite work, a separate increment) makes the
// body longer, so `content-length` must be recomputed before the request
// reaches the terminal/upstream. These tests pin the SEAM only -- that a
// filter can reach request headers that have not yet been forwarded, from
// wherever in the decode chain it decides to, and that the mutation survives
// all the way to what the terminal (the router stand-in) actually observes.

/// Where a [`HeaderMutatingFilter`] calls `modify_decoded_headers` from.
#[derive(Clone, Copy)]
enum HeaderMutationPoint {
    DecodeHeaders,
    DecodeData,
}

/// A decode filter that calls `cb.modify_decoded_headers(mutate)` from
/// whichever callback `call_from` selects, and records the `bool` the call
/// returned into `result`.
struct HeaderMutatingFilter {
    call_from: HeaderMutationPoint,
    mutate: Rc<dyn Fn(&mut RequestHeaders)>,
    result: Rc<RefCell<Option<bool>>>,
}

impl HttpFilter for HeaderMutatingFilter {
    fn decode_headers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        _headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        if matches!(self.call_from, HeaderMutationPoint::DecodeHeaders) {
            let mutate = self.mutate.clone();
            let applied = cb.modify_decoded_headers(&mut |h| mutate(h));
            *self.result.borrow_mut() = Some(applied);
        }
        FilterHeadersStatus::Continue
    }

    fn decode_data(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        _data: &mut Bytes,
        _end_stream: bool,
    ) -> FilterDataStatus {
        if matches!(self.call_from, HeaderMutationPoint::DecodeData) {
            let mutate = self.mutate.clone();
            let applied = cb.modify_decoded_headers(&mut |h| mutate(h));
            *self.result.borrow_mut() = Some(applied);
        }
        FilterDataStatus::Continue
    }
}

/// Run `filters` over `req` with a [`RecordingTerminal`] wired to capture the
/// request headers it observed, so a test can assert on what the
/// terminal/upstream actually sees rather than a local copy — mirrors
/// [`run_chain_req_with_route_table`] but for this increment's need
/// (`RecordingTerminal::seen_headers`, not a route table).
async fn run_chain_req_capturing_headers(
    filters: Vec<Box<dyn HttpFilter>>,
    log: Log,
    req: HttpRequestParts,
) -> (StatusCode, HeaderMap) {
    let seen_headers = Arc::new(Mutex::new(None));
    let terminal = RecordingTerminal {
        log,
        term_log: None,
        seen_body: Arc::new(Mutex::new(Bytes::new())),
        seen_request_id: Arc::new(Mutex::new(None)),
        seen_headers: Some(seen_headers.clone()),
        captured_body: Bytes::new(),
    };
    let mgr = FilterManager {
        filters,
        ctx: ChainCtx::new(Rc::new(RefCell::new(StreamInfo::default()))),
        terminal: Box::new(terminal),
        buffer_limit: DEFAULT_BUFFER_LIMIT,
    };
    let resp = mgr.run(req).await;
    let status = resp.head.status;
    let _ = resp.body.collect().await;
    let headers = seen_headers
        .lock()
        .unwrap()
        .clone()
        .expect("terminal must have run and recorded headers");
    (status, headers)
}

/// PROBE (WP-45 increment 2b): a filter mutating BOTH a direct parameter AND
/// `modify_decoded_headers` in the same callback must keep both mutations.
///
/// Increment 2a's version of this probe ran from `decode_headers`, mutating
/// the `headers` parameter directly AND via the seam in the same call --
/// that reproduced the data-loss bug this increment fixes (a stale
/// pre-callback clone spliced back over the direct mutation). Increment 2b's
/// fix for `decode_headers` specifically is to make the seam a documented
/// no-op there (see [`DecoderCallbacks::modify_decoded_headers`]'s doc) --
/// `decode_headers` already has direct `&mut RequestHeaders` access and
/// Rust's aliasing rules mean the seam genuinely cannot also hold a live
/// borrow of that same value at the same time. So this probe now runs from
/// `decode_data`, WP-45's actual load-bearing case: it directly mutates its
/// own `data: &mut Bytes` parameter (the one direct-mutation path
/// `decode_data` has) AND calls `modify_decoded_headers` (now a real,
/// clone-free borrow of the head -- see the trait doc) in the same
/// callback. Both must reach the terminal; neither may clobber the other.
struct BothPathsFilter;

impl HttpFilter for BothPathsFilter {
    fn decode_data(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        data: &mut Bytes,
        _end_stream: bool,
    ) -> FilterDataStatus {
        *data = Bytes::from_static(b"direct-body");
        cb.modify_decoded_headers(&mut |h| {
            h.headers.insert(
                HeaderName::from_static("x-via-seam"),
                HeaderValue::from_static("seam"),
            );
        });
        FilterDataStatus::Continue
    }
}

#[test]
fn probe_direct_and_seam_mutations_coexist() {
    block_on(async {
        let terminal = RecordingTerminal {
            log: log_of(),
            term_log: None,
            seen_body: Arc::new(Mutex::new(Bytes::new())),
            seen_request_id: Arc::new(Mutex::new(None)),
            seen_headers: Some(Arc::new(Mutex::new(None))),
            captured_body: Bytes::new(),
        };
        let seen_body = terminal.seen_body.clone();
        let seen_headers = terminal.seen_headers.clone().unwrap();
        let mgr = FilterManager {
            filters: vec![Box::new(BothPathsFilter)],
            ctx: ChainCtx::new(Rc::new(RefCell::new(StreamInfo::default()))),
            terminal: Box::new(terminal),
            buffer_limit: DEFAULT_BUFFER_LIMIT,
        };
        let resp = mgr.run(request(b"hi")).await;
        let _ = resp.body.collect().await;

        let seen = seen_headers
            .lock()
            .unwrap()
            .clone()
            .expect("terminal must have run and recorded headers");
        assert_eq!(
            seen.get("x-via-seam").map(|v| v.to_str().unwrap()),
            Some("seam"),
            "seam mutation lost"
        );
        assert_eq!(
            *seen_body.lock().unwrap(),
            Bytes::from_static(b"direct-body"),
            "DIRECT PARAMETER MUTATION WAS CLOBBERED"
        );
    });
}

/// WP-45 increment 2b fallback: `modify_decoded_headers` called from
/// `decode_headers` itself is a documented no-op (`false`, no mutation) --
/// see [`DecoderCallbacks::modify_decoded_headers`]'s doc for why. A
/// `decode_headers` filter already has direct `&mut RequestHeaders` access
/// through its own parameter; giving the seam a second live borrow of that
/// same value at the same time is impossible in safe Rust, and the
/// clone-based workaround increment 2a used is exactly what caused the
/// data-loss bug `probe_direct_and_seam_mutations_coexist` guards. (Before
/// this increment, this test asserted the opposite -- that the seam DID
/// reach the terminal from `decode_headers` -- which is what the clone/
/// splice-back mechanism enabled at the cost of that bug.)
#[test]
fn modify_decoded_headers_from_decode_headers_is_a_documented_no_op() {
    block_on(async {
        let log = log_of();
        let result = Rc::new(RefCell::new(None));
        let filter = HeaderMutatingFilter {
            call_from: HeaderMutationPoint::DecodeHeaders,
            mutate: Rc::new(|h: &mut RequestHeaders| {
                h.headers.insert(
                    HeaderName::from_static("x-injected"),
                    HeaderValue::from_static("from-headers-phase"),
                );
            }),
            result: result.clone(),
        };
        let (status, seen) =
            run_chain_req_capturing_headers(vec![Box::new(filter)], log, request(b"hi")).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            result.borrow().clone(),
            Some(false),
            "modify_decoded_headers must return false when called from \
             decode_headers -- see the trait doc's fallback note"
        );
        assert!(
            seen.get("x-injected").is_none(),
            "a no-op call must not mutate the headers either; seen: {seen:?}"
        );
    });
}

/// Load-bearing test for the whole increment: a filter that calls
/// `modify_decoded_headers` from `decode_data` (WP-45's actual case -- the
/// decision to inject body bytes, and so the need to fix up
/// `content-length`, is only made once body bytes have been scanned) ALSO
/// reaches the terminal. If only the `decode_headers` case worked, this seam
/// would be useless for WP-45.
#[test]
fn modify_decoded_headers_from_decode_data_reaches_the_terminal() {
    block_on(async {
        let log = log_of();
        let result = Rc::new(RefCell::new(None));
        let filter = HeaderMutatingFilter {
            call_from: HeaderMutationPoint::DecodeData,
            mutate: Rc::new(|h: &mut RequestHeaders| {
                h.headers.insert(
                    HeaderName::from_static("x-injected"),
                    HeaderValue::from_static("from-data-phase"),
                );
            }),
            result: result.clone(),
        };
        let (status, seen) =
            run_chain_req_capturing_headers(vec![Box::new(filter)], log, request(b"hi")).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(result.borrow().clone(), Some(true));
        assert_eq!(
            seen.get("x-injected").map(|v| v.to_str().unwrap()),
            Some("from-data-phase"),
            "the terminal must observe the header mutation made from \
             decode_data via modify_decoded_headers; seen: {seen:?}"
        );
    });
}

/// The motivating use: adding, replacing, and removing a header from
/// `decode_data` all take effect at the terminal -- specifically pinning
/// replacing `content-length` with a LARGER value (WP-45's actual need, once
/// it splices bytes into the body).
#[test]
fn modify_decoded_headers_add_replace_and_remove_all_take_effect() {
    block_on(async {
        let log = log_of();
        let result = Rc::new(RefCell::new(None));
        let filter = HeaderMutatingFilter {
            call_from: HeaderMutationPoint::DecodeData,
            mutate: Rc::new(|h: &mut RequestHeaders| {
                // Replace: content-length grows to reflect injected bytes.
                h.headers.insert(
                    HeaderName::from_static("content-length"),
                    HeaderValue::from_static("142"),
                );
                // Add: a header that wasn't present before.
                h.headers.insert(
                    HeaderName::from_static("x-brand-new"),
                    HeaderValue::from_static("added"),
                );
                // Remove: a header the request arrived with.
                h.headers.remove("x-drop-me");
            }),
            result: result.clone(),
        };

        let mut req = request(b"hi");
        req.head.headers.insert(
            HeaderName::from_static("content-length"),
            HeaderValue::from_static("2"),
        );
        req.head.headers.insert(
            HeaderName::from_static("x-drop-me"),
            HeaderValue::from_static("still-here"),
        );

        let (status, seen) =
            run_chain_req_capturing_headers(vec![Box::new(filter)], log, req).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(result.borrow().clone(), Some(true));
        assert_eq!(
            seen.get("content-length").map(|v| v.to_str().unwrap()),
            Some("142"),
            "content-length must be replaced with the larger, recomputed \
             value; seen: {seen:?}"
        );
        assert_eq!(
            seen.get("x-brand-new").map(|v| v.to_str().unwrap()),
            Some("added"),
            "a brand-new header must be added; seen: {seen:?}"
        );
        assert!(
            seen.get("x-drop-me").is_none(),
            "a removed header must not reach the terminal; seen: {seen:?}"
        );
    });
}

/// A filter that never calls `modify_decoded_headers` sees byte-identical
/// behavior to before this increment -- the seam is pure opt-in.
#[test]
fn a_filter_that_never_calls_modify_decoded_headers_is_unaffected() {
    block_on(async {
        let log = log_of();
        let mut req = request(b"hi");
        req.head.headers.insert(
            HeaderName::from_static("x-untouched"),
            HeaderValue::from_static("still-here"),
        );
        let probe = ProbeFilter::new("a", log.clone());
        let (status, seen) = run_chain_req_capturing_headers(vec![Box::new(probe)], log, req).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            seen.get("x-untouched").map(|v| v.to_str().unwrap()),
            Some("still-here"),
            "a filter that never calls modify_decoded_headers must not \
             change what the terminal sees; seen: {seen:?}"
        );
    });
}

/// A terminal double (ADR-0004 step 3: an ordinary `HttpFilter` at the last
/// decode position) that attempts `modify_decoded_headers` from its OWN
/// `decode_headers` -- i.e. strictly after the configured decode filter chain
/// has finished and `ChainCtx::decoded_headers_forwarded` is set. Records the
/// `bool` the call returned, and the headers it saw right after the attempt,
/// so a test can assert BOTH the return value and that nothing changed.
struct LateHeaderMutationTerminal {
    result: Rc<RefCell<Option<bool>>>,
    observed: Rc<RefCell<Option<HeaderMap>>>,
}

impl HttpFilter for LateHeaderMutationTerminal {
    fn decode_headers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        let applied = cb.modify_decoded_headers(&mut |h| {
            h.headers.insert(
                HeaderName::from_static("x-too-late"),
                HeaderValue::from_static("nope"),
            );
        });
        *self.result.borrow_mut() = Some(applied);
        *self.observed.borrow_mut() = Some(headers.headers.clone());
        FilterHeadersStatus::Continue
    }

    fn decode_data(
        &mut self,
        _cb: &mut dyn DecoderCallbacks,
        _data: &mut Bytes,
        _end_stream: bool,
    ) -> FilterDataStatus {
        FilterDataStatus::Continue
    }
}

impl TerminalHttpFilter for LateHeaderMutationTerminal {
    fn respond<'a>(
        &'a mut self,
        _cb: &'a mut dyn DecoderCallbacks,
    ) -> Pin<Box<dyn Future<Output = HttpResponseParts> + 'a>> {
        Box::pin(async move {
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

/// Once request headers can no longer affect the upstream request (the
/// configured decode filter chain has finished and the terminal is handling
/// the request), `modify_decoded_headers` is a no-op: it returns `false` AND
/// leaves the headers untouched.
#[test]
fn modify_decoded_headers_is_a_no_op_once_headers_are_forwarded() {
    block_on(async {
        let result = Rc::new(RefCell::new(None));
        let observed = Rc::new(RefCell::new(None));
        let terminal = LateHeaderMutationTerminal {
            result: result.clone(),
            observed: observed.clone(),
        };
        let mgr = FilterManager {
            filters: Vec::new(),
            ctx: ChainCtx::new(Rc::new(RefCell::new(StreamInfo::default()))),
            terminal: Box::new(terminal),
            buffer_limit: DEFAULT_BUFFER_LIMIT,
        };
        let resp = mgr.run(request(b"hi")).await;
        assert_eq!(resp.head.status, StatusCode::OK);

        assert_eq!(
            result.borrow().clone(),
            Some(false),
            "modify_decoded_headers must return false once headers have \
             already been forwarded to the terminal"
        );
        let seen = observed.borrow().clone().expect("terminal must have run");
        assert!(
            seen.get("x-too-late").is_none(),
            "a no-op call must not mutate the headers either; seen: {seen:?}"
        );
    });
}

// --- Token stats do not depend on access logging being configured ---------
//
// `FilterChainHandler::handle` wraps the response in `LoggingBody`, and
// `LoggingBody::finish` does two independent jobs at end-of-stream: it renders
// access-log lines, and it records GEN_AI_CLIENT_TOKEN_USAGE (WP-23 increment
// 6b). The wrap used to be gated on `access_loggers.is_empty()` alone, so a
// listener that configured `llmproxy.usage` for token metrics but no
// `access_log` silently recorded nothing -- the instrument was wired end to
// end and then skipped by the one branch that decides whether anything runs.
//
// This is the same shape as every other defect in that batch: a declared
// capability with no producer. It needs a test that switches token stats on
// and access logs OFF, because a suite that never configures that combination
// cannot regress it (ground rule 16).

/// Stamps both the usage AND the dialled cluster at end-of-stream --
/// `record_usage` needs a provider name, and it comes from
/// `StreamInfo::upstream_cluster` (ground rule #6: the member actually
/// dialled, not the routed name).
struct StampsUsageAndClusterFilter;

impl HttpFilter for StampsUsageAndClusterFilter {
    fn encode_data(
        &mut self,
        cb: &mut dyn EncoderCallbacks,
        _data: &mut Bytes,
        end_stream: bool,
    ) -> FilterDataStatus {
        if end_stream {
            let info = &mut *cb.stream_info();
            info.upstream_cluster = Some("provider:openai".to_string());
            info.llm.usage = Some(crate::stream_info::LlmTokenUsage {
                input_tokens: 11,
                cached_tokens: 0,
                cache_creation_tokens: 0,
                output_tokens: 7,
            });
        }
        FilterDataStatus::Continue
    }
}

struct StampsUsageAndClusterFilterFactory;

impl FilterInstanceFactory for StampsUsageAndClusterFilterFactory {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(StampsUsageAndClusterFilter)
    }
}

#[test]
fn token_stats_are_recorded_with_no_access_logs_configured() {
    use crate::stat_handles::{GenAiTokenStats, TokenUsageStatHandles};
    use proxy_observability::stats::{StatsControl, WorkerId as StatsWorkerId};

    block_on(async {
        let control = StatsControl::new(1);
        let handles = Arc::new(TokenUsageStatHandles::build(&control, ["provider:openai"]));
        let registry = control.registry();
        let token_stats = Arc::new(GenAiTokenStats::new(
            registry.clone(),
            handles.clone(),
            StatsWorkerId(0),
        ));

        let terminal_factory: Arc<dyn TerminalFilterInstanceFactory> =
            Arc::new(RecordingTerminalFactory {
                seen_body: Arc::new(Mutex::new(Bytes::new())),
                seen_request_id: Arc::new(Mutex::new(None)),
                seen_headers: None,
                term_log: None,
            });
        // The point of the test: `&[]` -- no access logs at all.
        let handler = FilterChainHandler::new_with_access_logs(
            vec![Arc::new(StampsUsageAndClusterFilterFactory)],
            terminal_factory,
            empty_route_table(),
            false,
            false,
            0,
            &[],
        )
        .expect("no sinks to open")
        .with_token_stats(token_stats);

        let resp = handler.handle(request(b"hi")).await;
        assert_eq!(resp.head.status, StatusCode::OK);
        resp.body.collect().await.expect("resp body must collect");

        let h = handles
            .for_provider("provider:openai")
            .expect("provider was resolved at build");
        assert_eq!(
            registry.value(h.input),
            11,
            "input tokens must be recorded even with no access_log configured"
        );
        assert_eq!(
            registry.value(h.output),
            7,
            "output tokens must be recorded even with no access_log configured"
        );
    });
}

/// Holds trailers with `StopIteration` but calls `continue_decoding()` from
/// inside the same callback -- the resume half of the S2.4 contract.
struct ResumingTrailerHoldFilter {
    log: Log,
}

impl HttpFilter for ResumingTrailerHoldFilter {
    fn decode_trailers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        _t: &mut RequestTrailers,
    ) -> FilterTrailersStatus {
        self.log
            .borrow_mut()
            .push("hold:decode_trailers".to_string());
        cb.continue_decoding();
        FilterTrailersStatus::StopIteration
    }
}

/// S2.4: the resume half. `decode_trailers_stop_iteration_holds_until_resumed`
/// is named for a resume it never performs -- its own comment says "here,
/// simply never" -- so it only ever proved the HOLD. The implementation reads
/// `continue_decoding()` as overriding a `StopIteration`, and does so through
/// a deliberately subtle reset: `continue_requested` is cleared immediately
/// before the `decode_trailers` call, because reaching that branch means
/// `decode_data` already continued and its leftover `true` would otherwise
/// read as this filter resuming its own trailer hold.
///
/// That reset is exactly the kind of reasoning that needs a test, and it had
/// none. If it were removed, `StopIteration` here would be indistinguishable
/// from `Continue` and the hold test alone would not notice.
#[test]
fn a_trailer_hold_resumed_in_the_same_callback_reaches_later_filters() {
    block_on(async {
        let log = log_of();
        let filters: Vec<Box<dyn HttpFilter>> = vec![
            Box::new(ResumingTrailerHoldFilter { log: log.clone() }),
            Box::new(ProbeFilter::new("b", log.clone())),
        ];
        let mut trailers = HeaderMap::new();
        trailers.insert("x-trace", HeaderValue::from_static("1"));
        let req = request_with_trailers(b"hi", trailers);
        run_chain_req(filters, log.clone(), req, DEFAULT_BUFFER_LIMIT).await;

        let entries = log.borrow().clone();
        assert!(
            entries.iter().any(|e| e == "hold:decode_trailers"),
            "the holding filter must have run: {entries:?}"
        );
        assert!(
            entries.iter().any(|e| e == "b:decode_trailers"),
            "continue_decoding() from inside decode_trailers must release the \
             hold, so a later filter DOES see the trailers (S2.4) -- this is \
             the case the hold-only test cannot distinguish; log: {entries:?}"
        );
    });
}
