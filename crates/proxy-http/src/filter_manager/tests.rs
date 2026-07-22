//! WP-11 chunk 1 tests: the S2 mechanics this chunk implements. The exhaustive
//! status-matrix conformance suite is chunk 2; these pin the engine's spine —
//! ordering (S2.1), the header-hold gotcha (S2.2), data statuses (S2.3),
//! trailers (S2.4), the buffer APIs (S2.7), and overflow → 413/500.

use std::cell::RefCell;
use std::rc::Rc;

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri};
use http_body_util::BodyExt;

use super::*;
use crate::filter::{FilterTrailersStatus, RequestHeaders};
use crate::handler::{HttpRequestParts, HttpResponseParts};

/// Shared call log: every filter appends `"<name>:<callback>"` so a test can
/// assert the exact interleaving the S2 spec prescribes.
type Log = Rc<RefCell<Vec<String>>>;

fn log_of() -> Log {
    Rc::new(RefCell::new(Vec::new()))
}

/// A configurable probe filter. Each field controls one callback's return.
struct ProbeFilter {
    name: &'static str,
    log: Log,
    decode_headers_status: FilterHeadersStatus,
    decode_data_status: FilterDataStatus,
    /// If set, `decode_data` calls `continue_decoding()` before returning.
    call_continue_decoding: bool,
    /// Bytes appended via `add_decoded_data` from `decode_headers`.
    add_decoded: Option<Bytes>,
    /// Bytes appended via `add_encoded_data` from `encode_headers`.
    add_encoded: Option<Bytes>,
}

impl ProbeFilter {
    fn new(name: &'static str, log: Log) -> Self {
        Self {
            name,
            log,
            decode_headers_status: FilterHeadersStatus::Continue,
            decode_data_status: FilterDataStatus::Continue,
            call_continue_decoding: false,
            add_decoded: None,
            add_encoded: None,
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
        self.decode_headers_status
    }

    fn decode_data(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        _data: &mut Bytes,
        _end_stream: bool,
    ) -> FilterDataStatus {
        self.record("decode_data");
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
        FilterTrailersStatus::Continue
    }

    fn encode_headers(
        &mut self,
        cb: &mut dyn EncoderCallbacks,
        _headers: &mut ResponseHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        self.record("encode_headers");
        if let Some(data) = &self.add_encoded {
            cb.add_encoded_data(data.clone(), false);
        }
        FilterHeadersStatus::Continue
    }

    fn encode_data(
        &mut self,
        _cb: &mut dyn EncoderCallbacks,
        _data: &mut Bytes,
        _end_stream: bool,
    ) -> FilterDataStatus {
        self.record("encode_data");
        FilterDataStatus::Continue
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
    }
}

/// A terminal handler that records that it ran and echoes a fixed 200 with the
/// request body it received (so tests can assert what reached the router).
struct RecordingTerminal {
    log: Log,
    seen_body: Rc<RefCell<Bytes>>,
}

impl StreamHandler for RecordingTerminal {
    fn handle<'a>(
        &'a self,
        req: HttpRequestParts,
    ) -> Pin<Box<dyn Future<Output = HttpResponseParts> + 'a>> {
        Box::pin(async move {
            self.log.borrow_mut().push("terminal".to_string());
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
