//! The OTLP/gRPC trace exporter -- drains a
//! [`crate::trace::SpanSink`]'s [`Receiver`](tokio::sync::mpsc::Receiver) and
//! ships batches of [`FinishedSpan`] to a real collector.
//!
//! The OTLP/gRPC exporters. They run on the CONTROL runtime, never touch a
//! request, and only hand already-owned data to a collector: finished spans,
//! or a read-only snapshot of the stats registry. Nothing here feeds back into
//! the data plane's [`proxy_config::ir`] (AGENTS.md invariant 2 covers Envoy
//! config protos, and OTLP protos never reach request code).
//!
//! - [`map_span`] and [`map_metrics`]: pure conversions to the OTLP wire types.
//! - [`run_trace_exporter`]: batches spans from a `SpanSink` until every sink
//!   clone is dropped, then flushes the last batch.
//! - [`run_metric_exporter`]: snapshots the registry on its own interval. It
//!   does not depend on tracing being configured.
//!
//! Traces and metrics are separate exporters so that metrics export does not
//! require tracing, and so that a slow trace RPC cannot delay a metric
//! snapshot (`docs/telemetry-design.md` §5.3). Each exporter counts its own
//! failures under a `signal` label, and enforces its own per-RPC deadline so a
//! silent collector costs one bounded timeout per attempt. Span losses are
//! published by the trace exporter, so they are visible even without OTLP
//! metric export.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc::Receiver;
use tonic::transport::{Channel, Endpoint};

use proxy_api::opentelemetry::proto::collector::metrics::v1::{
    metrics_service_client::MetricsServiceClient, ExportMetricsServiceRequest,
};
use proxy_api::opentelemetry::proto::collector::trace::v1::{
    trace_service_client::TraceServiceClient, ExportTraceServiceRequest,
};
use proxy_api::opentelemetry::proto::common::v1::{any_value, AnyValue, KeyValue};
use proxy_api::opentelemetry::proto::metrics::v1::{
    metric, number_data_point, AggregationTemporality, Histogram, HistogramDataPoint, Metric,
    NumberDataPoint, ResourceMetrics, ScopeMetrics, Sum,
};
use proxy_api::opentelemetry::proto::resource::v1::Resource;
use proxy_api::opentelemetry::proto::trace::v1::{
    span::SpanKind as OtlpSpanKind, status::StatusCode as OtlpStatusCode, ResourceSpans,
    ScopeSpans, Span, Status,
};

use crate::stats::{
    instruments, Handle, Instrument, InstrumentKind, Registry, StatsControl, WorkerId,
};
use crate::trace::{FinishedSpan, SpanDropCounter, SpanKind, SpanStatus};

/// Flush at this many buffered spans, or after [`BATCH_INTERVAL`] with at least
/// one span buffered. Neither bound alone is enough: a quiet proxy would hold
/// spans indefinitely, and a busy one would buffer without limit.
const MAX_BATCH: usize = 512;
const BATCH_INTERVAL: Duration = Duration::from_secs(5);

/// Upper bound on `TracingConfig::export_deadline`. `proxy-config` validates
/// against this constant, so the two cannot drift. A deadline longer than a
/// batch cycle would let a wedged export hold batches in memory across cycles.
pub const TRACE_EXPORT_DEADLINE_MAX: Duration = Duration::from_secs(60);

/// Convert a [`FinishedSpan`] into the OTLP wire type. Pure, so it is
/// unit-tested without a network.
///
/// Rust note: `..Default::default()` fills the `Span` fields this proxy never
/// sets. Their zero values mean "not used" on the wire.
pub fn map_span(span: &FinishedSpan) -> Span {
    Span {
        trace_id: span.context.trace_id.to_vec(),
        span_id: span.context.span_id.to_vec(),
        parent_span_id: span
            .context
            .parent_span_id
            .map(|p| p.to_vec())
            .unwrap_or_default(),
        name: span.name.clone(),
        kind: map_kind(span.kind) as i32,
        start_time_unix_nano: unix_nanos(span.start),
        end_time_unix_nano: unix_nanos(span.end),
        attributes: span
            .attributes
            .iter()
            .map(|(key, value)| string_attribute(key, value))
            .collect(),
        status: Some(map_status(span.status)),
        ..Default::default()
    }
}

fn string_attribute(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue(value.to_string())),
        }),
        // `key_strindex` is left at its default: this proxy emits no profiles.
        ..Default::default()
    }
}

fn map_kind(kind: SpanKind) -> OtlpSpanKind {
    match kind {
        SpanKind::Server => OtlpSpanKind::Server,
        SpanKind::Client => OtlpSpanKind::Client,
    }
}

fn map_status(status: SpanStatus) -> Status {
    let code = match status {
        SpanStatus::Unset => OtlpStatusCode::Unset,
        SpanStatus::Ok => OtlpStatusCode::Ok,
        SpanStatus::Error => OtlpStatusCode::Error,
    };
    Status {
        code: code as i32,
        ..Default::default()
    }
}

/// `SystemTime` -> unix-nanos. Span timestamps are wall-clock, since OTLP needs
/// an absolute epoch offset.
///
/// Rust note: `duration_since` fails only for a clock set before `UNIX_EPOCH`.
/// Falling back to zero beats failing a best-effort export over it.
fn unix_nanos(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64
}

fn build_resource(service_name: &str) -> Resource {
    Resource {
        attributes: vec![string_attribute("service.name", service_name)],
        ..Default::default()
    }
}

/// Convert every resolved instrument in `registry` into an OTLP
/// [`ExportMetricsServiceRequest`]. Pure, so it is unit-tested without a
/// network.
///
/// The registry yields one row per `(instrument, attribute set)`. OTLP wants
/// one [`Metric`] per instrument name, with one data point per attribute set.
/// Two `upstream_rq` rows must become one `Metric`, not two series.
///
/// Rust note: `group` is keyed by instrument name. The first row for a name
/// creates the entry, and later rows only push data points. `order` keeps the
/// names in first-seen order, because a `HashMap`'s iteration order is not
/// deterministic and the tests assert on it.
pub fn map_metrics(registry: &Registry, resource: &Resource) -> ExportMetricsServiceRequest {
    let now = unix_nanos(SystemTime::now());

    let mut counter_groups: HashMap<&'static str, (&'static Instrument, Vec<NumberDataPoint>)> =
        HashMap::new();
    let mut counter_order: Vec<&'static str> = Vec::new();
    for (instrument, attrs, value) in registry.counters() {
        let data_point = NumberDataPoint {
            attributes: attrs.iter().map(|(k, v)| string_attribute(k, v)).collect(),
            time_unix_nano: now,
            value: Some(number_data_point::Value::AsInt(value as i64)),
            ..Default::default()
        };
        counter_groups
            .entry(instrument.name)
            .or_insert_with(|| {
                counter_order.push(instrument.name);
                (instrument, Vec::new())
            })
            .1
            .push(data_point);
    }

    let mut histogram_groups: HashMap<
        &'static str,
        (&'static Instrument, Vec<HistogramDataPoint>),
    > = HashMap::new();
    let mut histogram_order: Vec<&'static str> = Vec::new();
    for (handle, instrument, attrs) in registry.histograms() {
        // `None`: the series was drained after `histograms()` listed it.
        let Some((snapshot, _)) = registry.histogram_view(handle) else {
            continue;
        };
        let explicit_bounds = instrument
            .buckets
            .expect("otlp::map_metrics: Histogram instrument with no bucket boundaries")
            .to_vec();
        let data_point = HistogramDataPoint {
            attributes: attrs.iter().map(|(k, v)| string_attribute(k, v)).collect(),
            time_unix_nano: now,
            count: snapshot.count,
            sum: Some(snapshot.sum),
            bucket_counts: snapshot.bucket_counts,
            explicit_bounds,
            ..Default::default()
        };
        histogram_groups
            .entry(instrument.name)
            .or_insert_with(|| {
                histogram_order.push(instrument.name);
                (instrument, Vec::new())
            })
            .1
            .push(data_point);
    }

    let mut metrics: Vec<Metric> = Vec::with_capacity(counter_order.len() + histogram_order.len());
    for name in counter_order {
        let (instrument, data_points) = counter_groups.remove(name).expect("just inserted");
        metrics.push(Metric {
            name: instrument.name.to_string(),
            unit: instrument.unit.to_string(),
            data: Some(metric::Data::Sum(Sum {
                data_points,
                aggregation_temporality: AggregationTemporality::Cumulative as i32,
                is_monotonic: instrument.kind == InstrumentKind::Counter,
            })),
            ..Default::default()
        });
    }
    for name in histogram_order {
        let (instrument, data_points) = histogram_groups.remove(name).expect("just inserted");
        metrics.push(Metric {
            name: instrument.name.to_string(),
            unit: instrument.unit.to_string(),
            data: Some(metric::Data::Histogram(Histogram {
                data_points,
                aggregation_temporality: AggregationTemporality::Cumulative as i32,
            })),
            ..Default::default()
        });
    }

    ExportMetricsServiceRequest {
        resource_metrics: vec![ResourceMetrics {
            resource: Some(resource.clone()),
            scope_metrics: vec![ScopeMetrics {
                metrics,
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
}

/// The span batching export loop. Runs until every `SpanSink` clone is dropped
/// and the last batch is flushed. `crates/proxy/src/main.rs` spawns it only
/// when tracing is configured.
///
/// # Failure handling
///
/// A failed or timed-out export logs, counts itself under `signal="traces"`,
/// counts the discarded spans into the drop ledger, and drops the batch.
/// Telemetry must never fail a request over an unreachable collector.
///
/// `export_deadline` bounds each RPC. Without it, a collector that accepts a
/// connection and then goes silent would park this task forever, and the sink
/// behind it would fill and drop.
///
/// Reconnection is left to `Endpoint::connect_lazy`, which reconnects on the
/// next call. "Try again next tick" is just calling `export` again.
pub async fn run_trace_exporter(
    mut rx: Receiver<FinishedSpan>,
    otlp_endpoint: String,
    service_name: String,
    registry: Arc<Registry>,
    failures: ExportCounters,
    export_deadline: Duration,
) {
    let mut client = match trace_client(&otlp_endpoint).await {
        Some(client) => client,
        None => return,
    };
    let resource = build_resource(&service_name);

    let mut batch: Vec<FinishedSpan> = Vec::with_capacity(MAX_BATCH);
    let mut ticker = tokio::time::interval(BATCH_INTERVAL);
    // Rust note: the first tick fires immediately, which is harmless because
    // `flush` is a no-op on an empty batch. `MissedTickBehavior::Delay` matters
    // more: after a slow flush, the next tick comes one interval later, not as a
    // burst of catch-up ticks.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            received = rx.recv() => {
                match received {
                    Some(span) => {
                        batch.push(span);
                        if batch.len() >= MAX_BATCH {
                            flush(&mut client, &resource, &mut batch, &registry, &failures, export_deadline).await;
                        }
                    }
                    None => {
                        // Every `SpanSink` clone is gone. Drain what is left and stop.
                        flush(&mut client, &resource, &mut batch, &registry, &failures, export_deadline).await;
                        return;
                    }
                }
            }
            _ = ticker.tick() => {
                flush(&mut client, &resource, &mut batch, &registry, &failures, export_deadline).await;
            }
        }
    }
}

/// The registry snapshot export loop. It is independent of
/// [`run_trace_exporter`]: its own task, interval and deadline, and a shared
/// read-only [`Registry`] as its only link to the trace path.
///
/// [`shutdown`] ends the task. A receiver that fires mid-sleep still gets one
/// last snapshot out.
///
/// # Why there is no retry, and no disk spool
///
/// The registry is cumulative, so a failed snapshot is superseded by the next
/// one (`docs/telemetry-design.md` §5.3). Retrying would hold memory across an
/// outage for data the next tick already contains. The failure is counted
/// instead.
pub async fn run_metric_exporter(
    registry: Arc<Registry>,
    otlp_endpoint: String,
    service_name: String,
    export_interval: Duration,
    export_deadline: Duration,
    health: MetricExportHealth,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) {
    let mut client = match metrics_client(&otlp_endpoint).await {
        Some(client) => client,
        None => return,
    };
    let resource = build_resource(&service_name);

    let mut ticker = tokio::time::interval(export_interval);
    // `Delay`, as in the trace loop: the next tick is one interval after the
    // previous export finished, not a burst of catch-up ticks.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                flush_metrics(
                    &mut client,
                    &registry,
                    &resource,
                    export_deadline,
                    &health,
                ).await;
            }
            // A closed sender (the caller dropped its `Sender` without
            // signalling) resolves this immediately, which is the correct
            // reading: nobody left to tell us when to stop.
            _ = &mut shutdown => {
                flush_metrics(
                    &mut client,
                    &registry,
                    &resource,
                    export_deadline,
                    &health,
                ).await;
                return;
            }
        }
    }
}

/// Pre-resolved handles for the two failure counters this module writes, plus
/// the span-drop republisher.
///
/// Resolved once at boot and only read afterwards. Both exporter tasks
/// increment through `WorkerId(0)`, a shard that is meaningless for a worker
/// but harmless here: every read sums across shards.
///
/// This is the sole publisher of `llmproxy_otel_spans_dropped`. Prometheus-only
/// deployments have no metric exporter, so the trace exporter must publish the
/// drops itself.
#[derive(Clone)]
pub struct ExportCounters {
    trace_failures: Handle,
    spans_dropped: Handle,
    /// Combined view of both trace-path drop sources. `Arc` because the sink
    /// owns the queue counter and this reads it; the batch counter is written
    /// by whoever flushes a failed export.
    drops: Arc<DropLedger>,
    /// Last published combined total. Only its increase is published to the
    /// monotonic registry counter.
    ///
    /// Rust note: an atomic keeps this `Sync` across awaits, where a `Cell`
    /// would not.
    last_republished: Arc<AtomicU64>,
}

/// The two trace-path span-loss sources, summed by [`ExportCounters`].
pub struct DropLedger {
    /// Queue drops: the sink's cumulative counter (channel full or receiver
    /// gone). `None` when tracing is off, so the ledger invents no drops.
    queue: Option<SpanDropCounter>,
    /// Batch drops: spans discarded by a failed or timed-out export. Counted
    /// where the batch size is known (`docs/telemetry-design.md` §5.5).
    batch: AtomicU64,
}

impl DropLedger {
    fn total(&self) -> u64 {
        let queue = self.queue.as_ref().map_or(0, SpanDropCounter::load);
        queue.wrapping_add(self.batch.load(Ordering::Relaxed))
    }
}

impl ExportCounters {
    /// Resolve the trace-side handles. The series are resolved even with
    /// tracing off, so a dashboard can tell "zero" from "not instrumented"
    /// (`docs/telemetry-design.md` §5.5). The ledger takes `None` when there is
    /// no sink, and then publishes nothing, so the zero stays honest.
    pub fn resolve(control: &StatsControl, sink_drops: Option<SpanDropCounter>) -> Self {
        let last = sink_drops.as_ref().map_or(0, SpanDropCounter::load);
        ExportCounters {
            trace_failures: control.resolve(
                &instruments::OTEL_EXPORT_FAILURES,
                &[("signal", instruments::EXPORT_SIGNAL_TRACES)],
            ),
            spans_dropped: control.resolve(&instruments::OTEL_SPANS_DROPPED, &[]),
            drops: Arc::new(DropLedger {
                queue: sink_drops,
                batch: AtomicU64::new(0),
            }),
            last_republished: Arc::new(AtomicU64::new(last)),
        }
    }

    /// Count one failed trace export and the spans its batch carried. The
    /// drops reach the registry on the next [`Self::publish_drops`].
    fn record_trace_failure(&self, registry: &Registry, batch_spans: u64) {
        registry.incr(WorkerId(0), self.trace_failures, 1);
        self.drops.batch.fetch_add(batch_spans, Ordering::Relaxed);
    }

    /// Move the delta of the drop ledger into `spans_dropped`. Runs after every
    /// flush, so queue drops show up without needing a failed export.
    fn publish_drops(&self, registry: &Registry) {
        let current = self.drops.total();
        let previous = self.last_republished.load(Ordering::Relaxed);
        let delta = current.wrapping_sub(previous);
        if delta == 0 {
            return;
        }
        self.last_republished.store(current, Ordering::Relaxed);
        registry.incr(WorkerId(0), self.spans_dropped, delta);
    }
}

/// The metric exporter's own self-instrument: the metric failure counter.
///
/// The metric exporter's own failure counter. Split from [`ExportCounters`] so
/// the metric exporter cannot increment the trace failure series. Span drops
/// stay with the trace exporter (see [`ExportCounters`]).
pub struct MetricExportHealth {
    failures: Handle,
}

impl MetricExportHealth {
    /// Resolve the metric-side failure handle. Call once at boot, even with
    /// no metric export configured, so the series exists from the first scrape.
    pub fn resolve(control: &StatsControl) -> Self {
        MetricExportHealth {
            failures: control.resolve(
                &instruments::OTEL_EXPORT_FAILURES,
                &[("signal", instruments::EXPORT_SIGNAL_METRICS)],
            ),
        }
    }

    /// Count one failed metric export.
    fn record_metric_failure(&self, registry: &Registry) {
        registry.incr(WorkerId(0), self.failures, 1);
    }
}

/// Build a lazily-connecting [`TraceServiceClient`], or `None` (after logging)
/// if the endpoint string is not a valid URI.
///
/// A malformed endpoint can never succeed on a later tick, so the exporter
/// gives up and drops events rather than holding them.
///
/// Rust note: the same "log once and give up" shape both exporters share, so
/// the logic lives in one place.
async fn trace_client(otlp_endpoint: &str) -> Option<TraceServiceClient<Channel>> {
    match Endpoint::from_shared(otlp_endpoint.to_string()) {
        Ok(endpoint) => Some(TraceServiceClient::new(endpoint.connect_lazy())),
        Err(err) => {
            tracing::error!(
                otlp_endpoint = %otlp_endpoint,
                error = %err,
                "OTLP exporter: invalid collector endpoint; tracing spans will be dropped"
            );
            None
        }
    }
}

/// The metric-path twin of [`trace_client`]. Each exporter gets its own
/// channel, so a wedged trace connection cannot stall metric export.
async fn metrics_client(otlp_endpoint: &str) -> Option<MetricsServiceClient<Channel>> {
    match Endpoint::from_shared(otlp_endpoint.to_string()) {
        Ok(endpoint) => Some(MetricsServiceClient::new(endpoint.connect_lazy())),
        Err(err) => {
            tracing::error!(
                otlp_endpoint = %otlp_endpoint,
                error = %err,
                "OTLP exporter: invalid collector endpoint; metrics will not be exported"
            );
            None
        }
    }
}

/// Export `batch` (if non-empty) and clear it, whatever the outcome. A failed
/// or timed-out batch counts both the failure and its span count, so a failure
/// always comes with the number of spans lost.
async fn flush(
    client: &mut TraceServiceClient<Channel>,
    resource: &Resource,
    batch: &mut Vec<FinishedSpan>,
    registry: &Registry,
    failures: &ExportCounters,
    export_deadline: Duration,
) {
    // Publish before the empty-batch return: queue drops accrue even when there
    // is nothing to export.
    failures.publish_drops(registry);
    if batch.is_empty() {
        return;
    }
    let spans: Vec<Span> = batch.iter().map(map_span).collect();
    let span_count = spans.len();
    let request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: Some(resource.clone()),
            scope_spans: vec![ScopeSpans {
                spans,
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    // The deadline bounds a collector that accepts the connection and then goes
    // silent. A cancelled tonic request is safe; its outcome is just unknown.
    let outcome = tokio::time::timeout(export_deadline, client.export(request)).await;
    match outcome {
        Ok(Ok(_)) => {}
        Ok(Err(err)) => {
            failures.record_trace_failure(registry, span_count as u64);
            tracing::warn!(
                error = %err,
                spans = span_count,
                "OTLP trace export failed; batch dropped"
            );
        }
        Err(_elapsed) => {
            // A timeout loses the batch just as a rejection does. Count both.
            failures.record_trace_failure(registry, span_count as u64);
            tracing::warn!(
                deadline_ms = export_deadline.as_millis() as u64,
                spans = span_count,
                "OTLP trace export timed out; batch dropped"
            );
        }
    }
    batch.clear();
    // Publish again so this flush's batch drops are visible immediately.
    failures.publish_drops(registry);
}

/// Export the registry's current cumulative state, bounded by `deadline`.
///
/// Same best-effort contract as [`flush`]. The registry is cumulative and is
/// **not** cleared on failure, so the next snapshot reports the totals anyway
/// (`docs/telemetry-design.md` §5.3).
async fn flush_metrics(
    client: &mut MetricsServiceClient<Channel>,
    registry: &Registry,
    resource: &Resource,
    deadline: Duration,
    health: &MetricExportHealth,
) {
    let request = map_metrics(registry, resource);
    // The deadline is the only bound on this `.await`. Without it a silent
    // connection would park the task and stop every later tick.
    match tokio::time::timeout(deadline, client.export(request)).await {
        Ok(Ok(_)) => {}
        Ok(Err(err)) => {
            health.record_metric_failure(registry);
            tracing::warn!(error = %err, "OTLP metrics export failed");
        }
        Err(_elapsed) => {
            health.record_metric_failure(registry);
            tracing::warn!(
                deadline_ms = deadline.as_millis() as u64,
                "OTLP metrics export timed out"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::TraceContext;

    fn sample_span(kind: SpanKind, status: SpanStatus) -> FinishedSpan {
        let ctx = TraceContext::new_root(true);
        FinishedSpan {
            context: ctx,
            name: "test-span".to_string(),
            kind,
            start: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
            end: SystemTime::UNIX_EPOCH + Duration::from_secs(1_001),
            attributes: vec![("http.request.method", "GET".to_string())],
            status,
        }
    }

    #[test]
    fn map_span_carries_ids_and_timestamps_exactly() {
        let span = sample_span(SpanKind::Server, SpanStatus::Ok);
        let mapped = map_span(&span);
        assert_eq!(mapped.trace_id, span.context.trace_id.to_vec());
        assert_eq!(mapped.span_id, span.context.span_id.to_vec());
        assert!(mapped.parent_span_id.is_empty());
        assert_eq!(mapped.start_time_unix_nano, 1_000_000_000_000);
        assert_eq!(mapped.end_time_unix_nano, 1_001_000_000_000);
        assert_eq!(mapped.name, "test-span");
    }

    #[test]
    fn map_span_sets_parent_span_id_for_a_child() {
        let root = TraceContext::new_root(true);
        let child = root.child();
        let span = FinishedSpan {
            context: child,
            ..sample_span(SpanKind::Client, SpanStatus::Unset)
        };
        let mapped = map_span(&span);
        assert_eq!(mapped.parent_span_id, root.span_id.to_vec());
    }

    #[test]
    fn map_span_kind_matches_server_and_client() {
        assert_eq!(
            map_span(&sample_span(SpanKind::Server, SpanStatus::Ok)).kind,
            OtlpSpanKind::Server as i32
        );
        assert_eq!(
            map_span(&sample_span(SpanKind::Client, SpanStatus::Ok)).kind,
            OtlpSpanKind::Client as i32
        );
    }

    #[test]
    fn map_span_status_round_trips_all_three_values() {
        assert_eq!(
            map_span(&sample_span(SpanKind::Server, SpanStatus::Unset))
                .status
                .unwrap()
                .code,
            OtlpStatusCode::Unset as i32
        );
        assert_eq!(
            map_span(&sample_span(SpanKind::Server, SpanStatus::Ok))
                .status
                .unwrap()
                .code,
            OtlpStatusCode::Ok as i32
        );
        assert_eq!(
            map_span(&sample_span(SpanKind::Server, SpanStatus::Error))
                .status
                .unwrap()
                .code,
            OtlpStatusCode::Error as i32
        );
    }

    #[test]
    fn map_span_converts_string_attributes() {
        let span = sample_span(SpanKind::Server, SpanStatus::Ok);
        let mapped = map_span(&span);
        assert_eq!(mapped.attributes.len(), 1);
        let attr = &mapped.attributes[0];
        assert_eq!(attr.key, "http.request.method");
        match &attr.value.as_ref().unwrap().value {
            Some(any_value::Value::StringValue(s)) => assert_eq!(s, "GET"),
            other => panic!("expected StringValue, got {other:?}"),
        }
    }

    #[test]
    fn build_resource_carries_service_name() {
        let resource = build_resource("my-service");
        assert_eq!(resource.attributes.len(), 1);
        assert_eq!(resource.attributes[0].key, "service.name");
        match &resource.attributes[0].value.as_ref().unwrap().value {
            Some(any_value::Value::StringValue(s)) => assert_eq!(s, "my-service"),
            other => panic!("expected StringValue, got {other:?}"),
        }
    }

    // The exporter loops need a collector and are covered end to end by
    // `crates/proxy/tests/otlp_trace_e2e.rs`. These tests stop at the pure
    // mapping functions and the counters.

    use crate::stats::{instruments, StatsControl, WorkerId};

    #[test]
    fn map_metrics_produces_one_sum_metric_per_counter_instrument() {
        let control = StatsControl::new(1);
        let openai = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "openai")]);
        let registry = control.registry();
        registry.incr(WorkerId(0), openai, 7);

        let resource = build_resource("test-service");
        let request = map_metrics(&registry, &resource);
        let metrics = &request.resource_metrics[0].scope_metrics[0].metrics;

        let upstream_rq = metrics
            .iter()
            .find(|m| m.name == "upstream_rq")
            .expect("upstream_rq metric present");
        assert_eq!(upstream_rq.unit, "{request}");
        let sum = match upstream_rq.data.as_ref().expect("data present") {
            metric::Data::Sum(sum) => sum,
            other => panic!("expected Data::Sum, got {other:?}"),
        };
        assert!(sum.is_monotonic);
        assert_eq!(
            sum.aggregation_temporality,
            AggregationTemporality::Cumulative as i32
        );
        assert_eq!(sum.data_points.len(), 1);
        let point = &sum.data_points[0];
        match point.value {
            Some(number_data_point::Value::AsInt(v)) => assert_eq!(v, 7),
            other => panic!("expected AsInt, got {other:?}"),
        }
        assert_eq!(point.attributes.len(), 1);
        assert_eq!(point.attributes[0].key, "cluster");
        match &point.attributes[0].value.as_ref().unwrap().value {
            Some(any_value::Value::StringValue(s)) => assert_eq!(s, "openai"),
            other => panic!("expected StringValue, got {other:?}"),
        }
    }

    #[test]
    fn map_metrics_groups_two_attribute_sets_into_one_metric_with_two_data_points() {
        let control = StatsControl::new(1);
        let openai = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "openai")]);
        let anthropic = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "anthropic")]);
        let registry = control.registry();
        registry.incr(WorkerId(0), openai, 3);
        registry.incr(WorkerId(0), anthropic, 5);

        let resource = build_resource("test-service");
        let request = map_metrics(&registry, &resource);
        let metrics = &request.resource_metrics[0].scope_metrics[0].metrics;

        let upstream_rq_metrics: Vec<&Metric> =
            metrics.iter().filter(|m| m.name == "upstream_rq").collect();
        assert_eq!(
            upstream_rq_metrics.len(),
            1,
            "two attribute sets on one instrument must collapse into ONE Metric, got {metrics:#?}"
        );
        let sum = match upstream_rq_metrics[0].data.as_ref().expect("data present") {
            metric::Data::Sum(sum) => sum,
            other => panic!("expected Data::Sum, got {other:?}"),
        };
        assert_eq!(sum.data_points.len(), 2);
    }

    #[test]
    fn map_metrics_produces_one_histogram_metric_matching_the_snapshot() {
        let control = StatsControl::new(1);
        let h = control.resolve_histogram(&instruments::UPSTREAM_RQ_TIME, &[("cluster", "x")]);
        let registry = control.registry();
        registry.observe(WorkerId(0), h, 12.0);
        registry.observe(WorkerId(0), h, 4000.0);
        let expected = registry.histogram_snapshot(h);

        let resource = build_resource("test-service");
        let request = map_metrics(&registry, &resource);
        let metrics = &request.resource_metrics[0].scope_metrics[0].metrics;

        let upstream_rq_time = metrics
            .iter()
            .find(|m| m.name == "upstream_rq_time")
            .expect("upstream_rq_time metric present");
        assert_eq!(upstream_rq_time.unit, "ms");
        let histogram = match upstream_rq_time.data.as_ref().expect("data present") {
            metric::Data::Histogram(histogram) => histogram,
            other => panic!("expected Data::Histogram, got {other:?}"),
        };
        assert_eq!(
            histogram.aggregation_temporality,
            AggregationTemporality::Cumulative as i32
        );
        assert_eq!(histogram.data_points.len(), 1);
        let point = &histogram.data_points[0];
        assert_eq!(point.count, expected.count);
        assert_eq!(point.sum, Some(expected.sum));
        assert_eq!(point.bucket_counts, expected.bucket_counts);
        assert_eq!(
            point.explicit_bounds,
            instruments::UPSTREAM_RQ_TIME.buckets.unwrap().to_vec()
        );
        assert_eq!(point.attributes.len(), 1);
        assert_eq!(point.attributes[0].key, "cluster");
    }

    #[test]
    fn map_metrics_on_an_empty_registry_produces_no_metrics() {
        let control = StatsControl::new(1);
        let registry = control.registry();
        let resource = build_resource("test-service");
        let request = map_metrics(&registry, &resource);
        assert!(request.resource_metrics[0].scope_metrics[0]
            .metrics
            .is_empty());
    }

    // ---- self-instrumentation: failure counters and the drop ledger -------

    /// The two failure series must carry distinct `signal` values, or an
    /// operator could not tell a trace outage from a metric one.
    #[test]
    fn both_export_failure_signals_resolve_to_distinct_series() {
        let control = StatsControl::new(1);
        let (sink, _rx) = crate::trace::SpanSink::new(1);
        let _counters = ExportCounters::resolve(&control, Some(sink.drop_counter()));
        let _health = MetricExportHealth::resolve(&control);
        let registry = control.registry();

        let signals: Vec<String> = registry
            .counters()
            .filter(|(instrument, _, _)| instrument.name == "llmproxy_otel_export_failures")
            .flat_map(|(_, attrs, _)| attrs.into_iter())
            .filter(|(key, _)| key == "signal")
            .map(|(_, value)| value)
            .collect();
        assert_eq!(
            signals,
            vec![
                instruments::EXPORT_SIGNAL_TRACES.to_string(),
                instruments::EXPORT_SIGNAL_METRICS.to_string()
            ],
            "expected exactly one series per signal, in resolution order"
        );
    }

    /// Resolving twice must not create a second pair of series.
    #[test]
    fn resolving_export_counters_twice_still_yields_one_series_per_signal() {
        let control = StatsControl::new(1);
        let (sink, _rx) = crate::trace::SpanSink::new(1);
        let _first = ExportCounters::resolve(&control, Some(sink.drop_counter()));
        let _again = ExportCounters::resolve(&control, Some(sink.drop_counter()));
        let _health = MetricExportHealth::resolve(&control);
        let registry = control.registry();

        let failure_series = registry
            .counters()
            .filter(|(instrument, _, _)| instrument.name == "llmproxy_otel_export_failures")
            .count();
        assert_eq!(failure_series, 2, "traces + metrics, no duplicates");
        let drop_series = registry
            .counters()
            .filter(|(instrument, _, _)| instrument.name == "llmproxy_otel_spans_dropped")
            .count();
        assert_eq!(drop_series, 1, "the drop series must not duplicate either");
    }

    /// A `None` sink (tracing off) still resolves both series, publishes
    /// nothing, and reports zero.
    #[test]
    fn a_none_sink_still_resolves_both_series_and_publishes_zero() {
        let control = StatsControl::new(1);
        let counters = ExportCounters::resolve(&control, None);
        let registry = control.registry();

        // Both series exist from resolution, on a process with no sink at all.
        let signals: Vec<String> = registry
            .counters()
            .filter(|(instrument, _, _)| instrument.name == "llmproxy_otel_export_failures")
            .flat_map(|(_, attrs, _)| attrs.into_iter())
            .filter(|(key, _)| key == "signal")
            .map(|(_, value)| value)
            .collect();
        assert!(signals.contains(&instruments::EXPORT_SIGNAL_TRACES.to_string()));
        let drop_series = registry
            .counters()
            .filter(|(instrument, _, _)| instrument.name == "llmproxy_otel_spans_dropped")
            .count();
        assert_eq!(drop_series, 1);

        // Publishing with no ledger source is a no-op, and never invents drops.
        counters.publish_drops(&registry);
        counters.publish_drops(&registry);
        assert_eq!(
            span_drops_value(&registry, &control),
            0,
            "a process with no SpanSink drops no spans and must not invent any"
        );
    }

    /// The ledger publishes deltas. A publish with no new drops adds nothing.
    #[test]
    fn publishing_reports_only_the_increase_in_drops() {
        let control = StatsControl::new(1);
        // Capacity 1 with the receiver retained and never drained: the first
        // emit lands in the buffer, every one after it is a drop. (Capacity 0
        // is not an option -- `tokio`'s bounded channel rejects it -- which is
        // also why this is a "fills up then drops" test rather than an
        // "always drops" one.)
        let (sink, _rx) = crate::trace::SpanSink::new(1);
        let counters = ExportCounters::resolve(&control, Some(sink.drop_counter()));
        let registry = control.registry();

        // Seeded at construction: the first publish must not report the
        // pre-construction value of the source counter as new drops.
        counters.publish_drops(&registry);
        assert_eq!(span_drops_value(&registry, &control), 0);

        for name in ["a", "b", "c", "d"] {
            sink.emit(sample_span_named(name));
        }
        counters.publish_drops(&registry);
        assert_eq!(
            span_drops_value(&registry, &control),
            3,
            "1 buffered + 3 dropped out of 4 emits"
        );

        // A publish with nothing new must not re-add the running total.
        counters.publish_drops(&registry);
        assert_eq!(span_drops_value(&registry, &control), 3);
    }

    /// A failed export must record the batch's span count as well as the
    /// failure, and both must reach the registry after one publish.
    #[test]
    fn a_failed_trace_export_counts_its_batchs_spans_into_the_drop_ledger() {
        let control = StatsControl::new(1);
        let (sink, _rx) = crate::trace::SpanSink::new(1);
        let counters = ExportCounters::resolve(&control, Some(sink.drop_counter()));
        let registry = control.registry();

        counters.record_trace_failure(&registry, 7);
        counters.record_trace_failure(&registry, 3);
        counters.publish_drops(&registry);

        let failures = failures_value(&registry, &control, instruments::EXPORT_SIGNAL_TRACES);
        assert_eq!(failures, 2, "two failed exports");
        assert_eq!(
            span_drops_value(&registry, &control),
            10,
            "the discarded batches' spans (7 + 3) must be counted, not just the failures"
        );
    }

    /// Queue and batch drops sum into one series rather than overwrite each other.
    #[test]
    fn queue_drops_and_batch_drops_sum_into_one_series() {
        let control = StatsControl::new(1);
        let (sink, _rx) = crate::trace::SpanSink::new(1);
        let counters = ExportCounters::resolve(&control, Some(sink.drop_counter()));
        let registry = control.registry();

        // 3 queue drops (1 buffered + 3 dropped of 4 emits).
        for name in ["a", "b", "c", "d"] {
            sink.emit(sample_span_named(name));
        }
        // 5 batch drops from two failed exports.
        counters.record_trace_failure(&registry, 2);
        counters.record_trace_failure(&registry, 3);
        counters.publish_drops(&registry);

        assert_eq!(
            span_drops_value(&registry, &control),
            8,
            "3 queue + 5 batch = 8 total losses"
        );
    }

    #[test]
    fn a_failed_metric_export_is_counted_under_the_metrics_signal_only() {
        let control = StatsControl::new(1);
        // Both series are resolved, so a zero here is a real zero.
        let (sink, _rx) = crate::trace::SpanSink::new(1);
        let _counters = ExportCounters::resolve(&control, Some(sink.drop_counter()));
        let health = MetricExportHealth::resolve(&control);
        let registry = control.registry();
        health.record_metric_failure(&registry);
        health.record_metric_failure(&registry);

        let per_signal = per_signal_values(&registry);
        assert!(
            per_signal.contains(&("metrics".to_string(), 2)),
            "{per_signal:?}"
        );
        assert!(
            per_signal.contains(&("traces".to_string(), 0)),
            "{per_signal:?}"
        );
    }

    #[test]
    fn a_failed_trace_export_is_counted_under_the_traces_signal_only() {
        let control = StatsControl::new(1);
        let (sink, _rx) = crate::trace::SpanSink::new(1);
        let counters = ExportCounters::resolve(&control, Some(sink.drop_counter()));
        let _health = MetricExportHealth::resolve(&control);
        let registry = control.registry();
        counters.record_trace_failure(&registry, 0);
        counters.publish_drops(&registry);

        let per_signal = per_signal_values(&registry);
        assert!(
            per_signal.contains(&("traces".to_string(), 1)),
            "{per_signal:?}"
        );
        assert!(
            per_signal.contains(&("metrics".to_string(), 0)),
            "{per_signal:?}"
        );
        // A failure carrying a zero-sized batch must not have manufactured any
        // drops -- the ledger only grows by what was actually discarded.
        assert_eq!(span_drops_value(&registry, &control), 0);
    }

    /// Reads `llmproxy_otel_spans_dropped`. Resolving is idempotent.
    fn span_drops_value(registry: &Registry, control: &StatsControl) -> u64 {
        let handle = control.resolve(&instruments::OTEL_SPANS_DROPPED, &[]);
        registry.value(handle)
    }

    /// Read one signal's `llmproxy_otel_export_failures` total out of the
    /// registry -- resolving is idempotent, so this adds no series.
    fn failures_value(registry: &Registry, control: &StatsControl, signal: &str) -> u64 {
        let handle = control.resolve(&instruments::OTEL_EXPORT_FAILURES, &[("signal", signal)]);
        registry.value(handle)
    }

    /// Every `(signal, failures)` pair currently in the registry.
    fn per_signal_values(registry: &Registry) -> Vec<(String, u64)> {
        registry
            .counters()
            .filter(|(instrument, _, _)| instrument.name == "llmproxy_otel_export_failures")
            .map(|(_, attrs, value)| {
                let signal = attrs
                    .iter()
                    .find(|(k, _)| k == "signal")
                    .map(|(_, v)| v.clone())
                    .expect("signal attribute present");
                (signal, value)
            })
            .collect()
    }

    /// A minimal `FinishedSpan` for drop-counting purposes -- the exporter
    /// never inspects a span before dropping it, so only the shape matters.
    fn sample_span_named(name: &str) -> FinishedSpan {
        FinishedSpan {
            context: TraceContext::new_root(true),
            name: name.to_string(),
            kind: SpanKind::Server,
            start: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
            end: SystemTime::UNIX_EPOCH + Duration::from_secs(1_001),
            attributes: Vec::new(),
            status: SpanStatus::Unset,
        }
    }
}
