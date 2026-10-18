//! Trace export's downstream body tee (ADR-0008 decisions 3 and 4), driven
//! through `FilterChainHandler::handle` so the admission point after the
//! decode chain and the `LoggingBody` wrap are the real ones. The auth
//! filter's pinning of the opt-in is covered in `proxy-filters`; here a
//! stand-in filter sets `AuthInfo` the same way, at `decode_headers`.

use std::sync::{mpsc, Mutex};

use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use http_body_util::BodyExt;
use proxy_observability::stats::StatsControl;
use proxy_observability::traces::capture::{
    CapturedTrace, PartialReason, TraceAdmission, TraceStats, BLOCK_BYTES,
};
use proxy_observability::traces::config::{TraceCodec, TraceExportConfig};
use proxy_observability::traces::gate::TraceGate;

use super::*;
use crate::filter::RequestHeaders;
use crate::handler::{DownstreamInfo, HttpRequestParts, HttpResponseParts};

fn config() -> TraceExportConfig {
    TraceExportConfig {
        directory: "/unused".into(),
        max_disk_bytes: 1 << 40,
        max_age: None,
        codec: TraceCodec::Gzip,
        max_request_body_bytes: 1 << 20,
        max_response_body_bytes: 1 << 20,
        max_memory_bytes: 64 << 20,
        max_queued_traces: 16,
        segment_max_bytes: 64 << 20,
        segment_max_age: std::time::Duration::from_secs(300),
        max_open_segments: 4,
        s3: None,
    }
}

struct Export {
    admission: Arc<TraceAdmission>,
    traces: mpsc::Receiver<Box<CapturedTrace>>,
    gate: Arc<TraceGate>,
    stats: StatsControl,
}

fn new_export(config: TraceExportConfig) -> Export {
    let stats = StatsControl::new(1);
    let gate = Arc::new(TraceGate::unpersisted());
    let (admission, traces) =
        TraceAdmission::new(&config, Arc::clone(&gate), TraceStats::resolve(&stats));
    Export {
        admission,
        traces,
        gate,
        stats,
    }
}

impl Export {
    /// One `llmproxy_trace_dropped_total` series.
    fn dropped(&self, reason: &str) -> u64 {
        let wanted = format!("envoy_llmproxy_trace_dropped_total{{reason=\"{reason}\"}} ");
        proxy_observability::stats::prometheus_render::render(&self.stats.registry())
            .lines()
            .find_map(|l| l.strip_prefix(&wanted).map(|v| v.parse().unwrap()))
            .unwrap_or_else(|| panic!("no dropped series for {reason}"))
    }

    fn all_dropped(&self) -> u64 {
        [
            "queue_full",
            "memory_budget",
            "emergency_disabled",
            "unsupported_protocol",
            "exporter_failed",
            "abandoned",
        ]
        .iter()
        .map(|r| self.dropped(r))
        .sum()
    }
}

/// Stands in for the auth filter: pins tenant and consent at
/// `decode_headers`, before any data callback, as the real one does.
struct ConsentFilter {
    opted_in: bool,
}

impl HttpFilter for ConsentFilter {
    fn decode_headers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        _headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        let mut info = cb.stream_info();
        info.auth.tenant = Some("tenant-a".into());
        info.auth.trace_export = self.opted_in;
        FilterHeadersStatus::Continue
    }
}

struct ConsentFactory(bool);

impl FilterInstanceFactory for ConsentFactory {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(ConsentFilter { opted_in: self.0 })
    }
}

/// Replaces the request body, as a model rewrite would, so a capture of the
/// forwarded body instead of the received one shows.
struct RewriteFilter;

impl HttpFilter for RewriteFilter {
    fn decode_data(
        &mut self,
        _cb: &mut dyn DecoderCallbacks,
        data: &mut Bytes,
        _end_stream: bool,
    ) -> FilterDataStatus {
        *data = Bytes::from_static(b"{\"model\":\"rewritten\"}");
        FilterDataStatus::Continue
    }
}

struct RewriteFactory;

impl FilterInstanceFactory for RewriteFactory {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(RewriteFilter)
    }
}

/// Refuses in the data pass, after consent is pinned, like a model grant.
struct RefuseFilter;

impl HttpFilter for RefuseFilter {
    fn decode_data(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        _data: &mut Bytes,
        _end_stream: bool,
    ) -> FilterDataStatus {
        cb.send_local_reply(StatusCode::FORBIDDEN, "model not allowed", None, "refused");
        FilterDataStatus::StopIterationNoBuffer
    }
}

struct RefuseFactory;

impl FilterInstanceFactory for RefuseFactory {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(RefuseFilter)
    }
}

/// Answers with `frames` as separate data frames of an SSE response and
/// records the body it was handed.
struct SseTerminal {
    frames: Vec<Bytes>,
    seen: Arc<Mutex<Option<Bytes>>>,
}

impl HttpFilter for SseTerminal {
    fn decode_data(
        &mut self,
        _cb: &mut dyn DecoderCallbacks,
        data: &mut Bytes,
        _end_stream: bool,
    ) -> FilterDataStatus {
        *self.seen.lock().unwrap() = Some(data.clone());
        FilterDataStatus::Continue
    }
}

impl TerminalHttpFilter for SseTerminal {
    fn respond<'a>(
        &'a mut self,
        _cb: &'a mut dyn DecoderCallbacks,
    ) -> Pin<Box<dyn Future<Output = HttpResponseParts> + 'a>> {
        Box::pin(async move {
            let mut headers = HeaderMap::new();
            headers.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("text/event-stream"),
            );
            let frames: Vec<Result<Frame<Bytes>, BodyError>> =
                self.frames.drain(..).map(|f| Ok(Frame::data(f))).collect();
            HttpResponseParts {
                head: ResponseHeaders {
                    status: StatusCode::OK,
                    headers,
                },
                body: local_boxed(StreamBody::new(futures::stream::iter(frames))),
                upgrade: None,
            }
        })
    }
}

struct SseFactory {
    frames: Vec<Bytes>,
    seen: Arc<Mutex<Option<Bytes>>>,
}

impl TerminalFilterInstanceFactory for SseFactory {
    fn create_terminal_filter(&self) -> Box<dyn TerminalHttpFilter> {
        Box::new(SseTerminal {
            frames: self.frames.clone(),
            seen: Arc::clone(&self.seen),
        })
    }
}

const SSE: [&[u8]; 3] = [
    b"data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n",
    b"data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n",
    b"data: [DONE]\n\n",
];

fn build_handler(
    filters: Vec<Arc<dyn FilterInstanceFactory>>,
    frames: &[&'static [u8]],
    export: Option<&Export>,
) -> (FilterChainHandler, Arc<Mutex<Option<Bytes>>>) {
    let seen = Arc::new(Mutex::new(None));
    let terminal = Arc::new(SseFactory {
        frames: frames.iter().map(|f| Bytes::from_static(f)).collect(),
        seen: Arc::clone(&seen),
    });
    let table = Arc::new(
        RouteTable::new(
            "t".to_string(),
            Vec::new(),
            std::collections::BTreeMap::new(),
        )
        .expect("empty table is valid"),
    );
    let mut handler = FilterChainHandler::new(filters, terminal, table, false, false, 0);
    if let Some(export) = export {
        handler = handler.with_traces(Arc::clone(&export.admission));
    }
    (handler, seen)
}

fn request(body: &'static [u8]) -> HttpRequestParts {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    HttpRequestParts {
        head: RequestHeaders {
            method: Method::POST,
            uri: Uri::from_static("http://example.test/v1/chat/completions"),
            headers,
        },
        body: bytes_to_seam_body(Bytes::from_static(body), None),
        downstream: DownstreamInfo::loopback(),
        on_upgrade: None,
    }
}

/// Every data frame the client is handed, in order, each as its own entry.
async fn client_frames(resp: HttpResponseParts) -> Vec<Bytes> {
    let mut body = resp.body;
    let mut frames = Vec::new();
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame.expect("no body error").into_data() {
            frames.push(data);
        }
    }
    frames
}

fn block_on<F: Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(f)
}

const BODY: &[u8] = b"{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}";

/// A tenant that did not opt in, on a proxy with export enabled: no capture,
/// nothing reserved at any point, no counted loss. The reservation counters
/// are the only way a capture byte is ever allocated, so their staying at
/// zero is the allocation check.
#[test]
fn a_tenant_that_did_not_opt_in_retains_nothing() {
    block_on(async {
        let export = new_export(config());
        let (handler, _) =
            build_handler(vec![Arc::new(ConsentFactory(false))], &SSE, Some(&export));
        let resp = handler.handle(request(BODY)).await;
        assert_eq!(export.admission.held_slots(), 0, "admission never ran");
        client_frames(resp).await;
        assert!(export.traces.try_recv().is_err());
        assert_eq!(export.admission.retained_bytes(), 0);
        assert_eq!(export.admission.held_slots(), 0);
        assert_eq!(export.all_dropped(), 0, "no consent is not a loss");
    });
}

/// The training pair: the request exactly as received, before a filter
/// replaced it, and the response exactly as delivered. The client sees the
/// same frames, one for one, with capture on and off.
#[test]
fn an_opted_in_request_captures_the_body_as_received_and_the_frames_as_delivered() {
    block_on(async {
        let filters = || -> Vec<Arc<dyn FilterInstanceFactory>> {
            vec![Arc::new(ConsentFactory(true)), Arc::new(RewriteFactory)]
        };
        let (plain, _) = build_handler(filters(), &SSE, None);
        let without_capture = client_frames(plain.handle(request(BODY)).await).await;

        let export = new_export(config());
        let (handler, seen) = build_handler(filters(), &SSE, Some(&export));
        let with_capture = client_frames(handler.handle(request(BODY)).await).await;

        assert_eq!(
            with_capture, without_capture,
            "frame boundaries are unchanged"
        );
        assert_eq!(with_capture.len(), SSE.len());
        assert_eq!(
            seen.lock().unwrap().as_deref(),
            Some(&b"{\"model\":\"rewritten\"}"[..]),
            "the upstream got the rewritten body"
        );
        let mut trace = export.traces.try_recv().expect("one trace handed over");
        assert_eq!(
            trace.request, BODY,
            "the body as received, not as forwarded"
        );
        assert_eq!(trace.response_bytes(), SSE.concat());
        assert!(trace.partial.is_empty());
        assert_eq!(trace.meta.path, "/v1/chat/completions");
        assert_eq!(trace.meta.status, Some(200));
        assert_eq!(
            trace.meta.response_content_type.as_deref(),
            Some("text/event-stream")
        );
        assert_eq!(trace.record.tenant_id, "tenant-a");
        assert!(trace.record.event_id.ends_with(":terminal"));
        assert!(export.traces.try_recv().is_err(), "exactly one trace");
        trace.mark_accounted();
        drop(trace);
        assert_eq!(export.admission.retained_bytes(), 0);
        assert_eq!(export.admission.held_slots(), 0);
    });
}

/// Over a cap, that direction keeps its first bytes and stops; the trace is
/// marked partial and still handed over. A response larger than one block
/// is copied into blocks without reallocating.
#[test]
fn over_a_cap_the_trace_is_partial_and_still_handed_over() {
    block_on(async {
        let big_frame: &'static [u8] = Box::leak(vec![b'x'; BLOCK_BYTES + 100].into_boxed_slice());
        let mut cfg = config();
        cfg.max_request_body_bytes = 10;
        cfg.max_response_body_bytes = BLOCK_BYTES + 50;
        let export = new_export(cfg);
        let (handler, _) = build_handler(
            vec![Arc::new(ConsentFactory(true))],
            &[big_frame, b"tail"],
            Some(&export),
        );
        let frames = client_frames(handler.handle(request(BODY)).await).await;
        assert_eq!(
            frames.concat().len(),
            BLOCK_BYTES + 104,
            "the client gets everything"
        );

        let trace = export
            .traces
            .try_recv()
            .expect("handed over despite the caps");
        assert_eq!(trace.request, &BODY[..10]);
        assert_eq!(trace.response_len, BLOCK_BYTES + 50);
        assert_eq!(
            trace.response.len(),
            2,
            "one full block, then the rest of the cap"
        );
        assert_eq!(
            trace.partial,
            vec![
                PartialReason::RequestOverCap,
                PartialReason::ResponseOverCap
            ]
        );
    });
}

/// Slot and byte exhaustion refuse before anything is copied, and each is
/// counted with its own reason. A queued, unconsumed trace holds its slot.
#[test]
fn exhausted_budgets_drop_before_allocating_and_count_the_reason() {
    block_on(async {
        let mut cfg = config();
        cfg.max_queued_traces = 1;
        let export = new_export(cfg);
        let (handler, _) = build_handler(vec![Arc::new(ConsentFactory(true))], &SSE, Some(&export));
        client_frames(handler.handle(request(BODY)).await).await;
        let held = export.admission.retained_bytes();
        client_frames(handler.handle(request(BODY)).await).await;
        assert_eq!(export.dropped("queue_full"), 1);
        assert_eq!(
            export.admission.retained_bytes(),
            held,
            "nothing more retained"
        );
        assert!(export.traces.try_recv().is_ok());
        assert!(export.traces.try_recv().is_err());

        // The request fits, the first response block does not: the response
        // direction stops before allocating and the trace is still written.
        let mut cfg = config();
        cfg.max_memory_bytes = BODY.len() + 10;
        let export = new_export(cfg);
        let (handler, _) = build_handler(vec![Arc::new(ConsentFactory(true))], &SSE, Some(&export));
        client_frames(handler.handle(request(BODY)).await).await;
        let trace = export
            .traces
            .try_recv()
            .expect("handed over without its response");
        assert_eq!(trace.request, BODY);
        assert_eq!(trace.response_len, 0);
        assert_eq!(trace.partial, vec![PartialReason::MemoryBudget]);
        assert_eq!(export.admission.retained_bytes(), BODY.len());

        let mut cfg = config();
        cfg.max_memory_bytes = BODY.len() - 1;
        let export = new_export(cfg);
        let (handler, _) = build_handler(vec![Arc::new(ConsentFactory(true))], &SSE, Some(&export));
        client_frames(handler.handle(request(BODY)).await).await;
        assert_eq!(export.dropped("memory_budget"), 1);
        assert!(export.traces.try_recv().is_err());
        assert_eq!(export.admission.retained_bytes(), 0);
        assert_eq!(export.admission.held_slots(), 0);
    });
}

/// A refusal sent by a filter after consent was pinned is the response the
/// tenant's agent received, so it is captured with its reply body.
#[test]
fn a_local_reply_after_consent_is_captured() {
    block_on(async {
        let export = new_export(config());
        let (handler, seen) = build_handler(
            vec![Arc::new(ConsentFactory(true)), Arc::new(RefuseFactory)],
            &SSE,
            Some(&export),
        );
        let resp = handler.handle(request(BODY)).await;
        assert_eq!(resp.head.status, StatusCode::FORBIDDEN);
        let delivered = client_frames(resp).await.concat();
        assert!(seen.lock().unwrap().is_none(), "the terminal never ran");
        let trace = export.traces.try_recv().expect("the refusal is captured");
        assert_eq!(trace.request, BODY);
        assert_eq!(trace.response_bytes(), delivered);
        assert_eq!(trace.meta.status, Some(403));
    });
}

/// An emergency disable while a response streams discards that capture at
/// its next frame, releases what it held, counts it once, and leaves the
/// client's stream alone.
#[test]
fn an_emergency_disable_mid_stream_discards_the_capture() {
    block_on(async {
        let export = new_export(config());
        let (handler, _) = build_handler(vec![Arc::new(ConsentFactory(true))], &SSE, Some(&export));
        let mut body = handler.handle(request(BODY)).await.body;
        let first = body.frame().await.unwrap().unwrap();
        assert!(first.is_data());
        assert!(export.admission.retained_bytes() > 0);

        export.gate.set_disabled(true, 0).unwrap();
        assert!(body.frame().await.unwrap().unwrap().is_data());
        assert_eq!(
            export.admission.retained_bytes(),
            0,
            "released at the next frame, not at the end of the stream"
        );
        let mut rest = 1;
        while let Some(frame) = body.frame().await {
            if frame.unwrap().is_data() {
                rest += 1;
            }
        }
        drop(body);
        assert_eq!(rest, SSE.len() - 1, "the client stream is untouched");
        assert!(export.traces.try_recv().is_err());
        assert_eq!(export.dropped("emergency_disabled"), 1);
        assert_eq!(export.dropped("abandoned"), 0, "counted once");
        assert_eq!(export.admission.retained_bytes(), 0);
        assert_eq!(export.admission.held_slots(), 0);

        // Reopened, but the next request is admitted under the new
        // generation and captured normally.
        export.gate.set_disabled(false, 1).unwrap();
        client_frames(handler.handle(request(BODY)).await).await;
        assert!(export.traces.try_recv().is_ok());
    });
}

/// A closed gate admits nothing, and an exporter that has stopped loses the
/// hand-off visibly rather than silently.
#[test]
fn a_closed_gate_admits_nothing_and_a_stopped_exporter_counts_its_losses() {
    block_on(async {
        let export = new_export(config());
        export.gate.set_disabled(true, 0).unwrap();
        let (handler, _) = build_handler(vec![Arc::new(ConsentFactory(true))], &SSE, Some(&export));
        client_frames(handler.handle(request(BODY)).await).await;
        assert!(export.traces.try_recv().is_err());
        assert_eq!(export.admission.held_slots(), 0);

        let Export {
            admission,
            traces,
            stats,
            gate,
        } = new_export(config());
        let stopped = Export {
            admission,
            traces: mpsc::channel().1,
            stats,
            gate,
        };
        drop(traces);
        let (handler, _) =
            build_handler(vec![Arc::new(ConsentFactory(true))], &SSE, Some(&stopped));
        client_frames(handler.handle(request(BODY)).await).await;
        assert_eq!(stopped.dropped("exporter_failed"), 1);
        assert_eq!(stopped.admission.held_slots(), 0);
    });
}

/// An upgraded session's bytes bypass the response tee, so it is not
/// admitted at all, and the loss is counted.
#[test]
fn an_upgrade_request_is_not_admitted() {
    block_on(async {
        let export = new_export(config());
        let (handler, _) = build_handler(vec![Arc::new(ConsentFactory(true))], &SSE, Some(&export));
        let mut req = request(BODY);
        let mut upgradable = http::Request::new(());
        req.on_upgrade = Some(hyper::upgrade::on(&mut upgradable));
        client_frames(handler.handle(req).await).await;
        assert!(export.traces.try_recv().is_err());
        assert_eq!(export.dropped("unsupported_protocol"), 1);
        assert_eq!(export.admission.held_slots(), 0);
    });
}
