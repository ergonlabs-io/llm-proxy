//! WP-51 increment 3a: the OTLP/gRPC trace exporter -- drains a
//! [`crate::trace::SpanSink`]'s [`Receiver`](tokio::sync::mpsc::Receiver) and
//! ships batches of [`FinishedSpan`] to a real collector.
//!
//! This is the one module in the data-plane-adjacent crates that names a
//! generated OTLP proto (`proxy_api::opentelemetry`). Ground rule #2
//! ("protos never escape `proxy-config`/`proxy-xds`") is about *Envoy
//! config* protos never reaching request-handling code -- see `ir.rs`'s own
//! module doc for why that boundary matters (strict-mode field coverage,
//! IR as the one API surface every lane codes against). OTLP export is a
//! different protocol serving a different purpose: [`run_exporter`] runs
//! entirely on the CONTROL runtime (`crates/proxy/src/main.rs`'s
//! `run_serve`, next to the config-publisher tasks), never touches a
//! request, and its only job is to hand already-finished, already-owned
//! [`FinishedSpan`] values to a collector over the wire. Nothing here is
//! parsed out of, or fed back into, the [`proxy_config::ir`] the data plane
//! actually runs on.
//!
//! Two pieces:
//! - [`map_span`]: pure `FinishedSpan -> proto Span` conversion, unit-tested
//!   on its own (no network).
//! - [`run_exporter`]: the batching loop. Owns the `Receiver` end of a
//!   `SpanSink` for its whole life; returns once every `SpanSink` clone has
//!   been dropped (workers gone) and the last batch is flushed.

use std::collections::HashMap;
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

use crate::stats::{Instrument, InstrumentKind, Registry};
use crate::trace::{FinishedSpan, SpanKind, SpanStatus};

/// Flush whichever comes first: this many buffered spans, or
/// [`BATCH_INTERVAL`] elapsing with at least one span buffered. Matches the
/// module brief's "batches on an interval or a max-batch size" -- neither
/// bound alone is right: a quiet proxy would otherwise hold a handful of
/// spans indefinitely, and a busy one would otherwise buffer unboundedly
/// between ticks.
const MAX_BATCH: usize = 512;
const BATCH_INTERVAL: Duration = Duration::from_secs(5);

/// Convert a [`FinishedSpan`] into the OTLP wire type. Pure -- no I/O, so
/// this is unit-tested directly rather than only through [`run_exporter`]'s
/// network path.
///
/// Rust note: `..Default::default()` fills every `Span` field this proxy
/// never populates (`trace_state`, `flags`, events, links, drop counts) --
/// prost generates `Default` for every message type, and the zero value for
/// each of those fields (empty string, `0`, empty `Vec`) is exactly what
/// "not used" means on the wire, so there is nothing to write by hand here.
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
        // `key_strindex` (profiles-dictionary interning, a newer addition to
        // this message) is left at its `Default` -- this proxy never emits
        // profile signals, only traces, so there is no dictionary to index
        // into.
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

/// `SystemTime` -> unix-nanos, per [`FinishedSpan`]'s own doc comment on why
/// its timestamps are `SystemTime` (wall clock, convertible to an absolute
/// epoch offset) rather than `Instant` (monotonic, not convertible at all).
///
/// Rust note: `duration_since` returns `Err` only when `t` is *before*
/// `UNIX_EPOCH` -- a clock that has never been set, not a real failure this
/// exporter can do anything about. `unwrap_or_default()` (zero duration, so
/// unix-nanos `0`) is a saner span timestamp than propagating that error out
/// of a best-effort telemetry path (this whole module's contract, per its
/// module doc: never take the proxy down over an export detail).
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
/// [`ExportMetricsServiceRequest`]. Pure -- no I/O, so unit-tested directly
/// (mirroring [`map_span`]) rather than only through [`run_exporter`]'s
/// network path.
///
/// # Grouping
///
/// [`Registry::counters`]/[`Registry::histograms`] yield one row per
/// `(instrument, attribute set)` pair -- exactly OTel's own measurement
/// model (module doc, `stats.rs` Decision 1), but OTLP wants the opposite
/// shape: **one [`Metric`] per instrument NAME**, carrying one data point per
/// attribute set. Two `upstream_rq` rows (`cluster=openai`,
/// `cluster=anthropic`) must become ONE `Metric` named `upstream_rq` with two
/// [`NumberDataPoint`]s, not two separate `Metric`s that would each look like
/// a distinct time series to a collector.
///
/// Rust note: `group` is a `HashMap` keyed by `instrument.name` whose value
/// is `(&'static Instrument, Vec<data point>)` -- the first row seen for a
/// name creates the entry (`or_insert_with`) and every later row for the
/// same name only pushes a data point, never touches the key again. `order`
/// is a plain `Vec<&str>` of names in first-seen order: a `HashMap`'s
/// iteration order is unspecified, and this function's own doc promises a
/// deterministic (first-seen) order so a test can assert on it.
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
        let snapshot = registry.histogram_snapshot(handle);
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

/// The batching export loop. Runs until `rx` is closed (every clone of the
/// `SpanSink` that fed it has been dropped) and its last batch is flushed --
/// `crates/proxy/src/main.rs` spawns this on the control runtime only when
/// `snapshot.tracing` is `Some`; tracing-off means this function is never
/// called at all, matching the module brief's "zero cost when off".
///
/// # Failure handling
///
/// Export failure (a connect error, the collector rejecting the batch, a
/// timeout -- `tonic::Status` covers all three uniformly) logs and drops the
/// batch. Telemetry must never take the proxy down or fail a request over an
/// unreachable collector; see this crate's `trace::SpanSink::emit` for the
/// same trade one layer up (a full channel drops instead of blocking a
/// request).
///
/// Reconnection is deliberately NOT hand-rolled: `Endpoint::connect_lazy`
/// builds a `Channel` that establishes its connection lazily on first use
/// and reconnects on its own for every subsequent call through tower's
/// built-in retry-connect behavior, so "try again next tick" falls out of
/// just calling `export` again -- there is no retry loop here holding a
/// batch hostage while a collector is down.
pub async fn run_exporter(
    mut rx: Receiver<FinishedSpan>,
    otlp_endpoint: String,
    service_name: String,
    registry: Arc<Registry>,
) {
    let channel = match Endpoint::from_shared(otlp_endpoint.clone()) {
        Ok(endpoint) => endpoint.connect_lazy(),
        Err(err) => {
            // An endpoint string that can't even be parsed into an `Endpoint`
            // (WP-51's `TracingConfig::otlp_endpoint` is validated non-empty
            // at config-lowering time, but not that it's a well-formed URI --
            // see that field's doc) can never succeed on any later tick
            // either, so there is nothing to reconnect: log once and let this
            // task end. Every span emitted from here on is simply dropped by
            // `SpanSink::emit` (the channel it feeds isn't drained by
            // anything, exactly the "closed receiver" case that function's
            // own doc already covers), not held anywhere.
            tracing::error!(
                otlp_endpoint = %otlp_endpoint,
                error = %err,
                "OTLP exporter: invalid collector endpoint; tracing spans will be dropped"
            );
            return;
        }
    };
    // Rust note: `Channel` is cheaply `Clone` (an `Arc`-backed handle onto
    // the same underlying connection pool -- tonic's own doc says as much),
    // so both clients share one lazily-established connection to the same
    // collector endpoint rather than each dialing their own.
    let mut client = TraceServiceClient::new(channel.clone());
    let mut metrics_client = MetricsServiceClient::new(channel);
    let resource = build_resource(&service_name);

    let mut batch: Vec<FinishedSpan> = Vec::with_capacity(MAX_BATCH);
    let mut ticker = tokio::time::interval(BATCH_INTERVAL);
    // Rust note: the first tick of `tokio::time::interval` fires immediately
    // (not after one full period) -- harmless here since `flush` is a no-op
    // on an empty batch, but `MissedTickBehavior::Delay` (rather than the
    // default `Burst`) still matters: if a flush itself runs long (a slow
    // collector), the NEXT tick should be `BATCH_INTERVAL` after that flush
    // finishes, not fire a burst of catch-up ticks back to back.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            received = rx.recv() => {
                match received {
                    Some(span) => {
                        batch.push(span);
                        if batch.len() >= MAX_BATCH {
                            flush(&mut client, &resource, &mut batch).await;
                        }
                    }
                    None => {
                        // Every `SpanSink` clone is gone -- drain whatever's
                        // left, then this task has nothing further to do.
                        // One last metric export too, same "final flush on
                        // shutdown" contract as spans.
                        flush(&mut client, &resource, &mut batch).await;
                        flush_metrics(&mut metrics_client, &registry, &resource).await;
                        return;
                    }
                }
            }
            _ = ticker.tick() => {
                // Metrics are exported on the tick only, never on `rx.recv()`
                // -- unlike spans (which arrive one at a time and get
                // batched), a metric export always reads the registry's
                // CURRENT cumulative state, so there is nothing to batch and
                // no reason to export more often than the interval already
                // driving the span flush.
                flush(&mut client, &resource, &mut batch).await;
                flush_metrics(&mut metrics_client, &registry, &resource).await;
            }
        }
    }
}

/// Export `batch` (if non-empty) and clear it, regardless of outcome -- see
/// [`run_exporter`]'s doc on why a failure logs and drops rather than
/// retaining the batch for another attempt.
async fn flush(
    client: &mut TraceServiceClient<Channel>,
    resource: &Resource,
    batch: &mut Vec<FinishedSpan>,
) {
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
    // Drop the batch either way -- `Vec::clear` after the `.await`, not
    // before: `batch` (the caller's buffer) has to stay populated for the
    // `spans`/`request` build above regardless of what `export` returns.
    if let Err(err) = client.export(request).await {
        tracing::warn!(
            error = %err,
            spans = span_count,
            "OTLP trace export failed; batch dropped"
        );
    }
    batch.clear();
}

/// Export the registry's current cumulative state. Same best-effort contract
/// as [`flush`]: a failure logs and moves on -- a metrics collector being
/// unreachable must never take the proxy down or hold any state hostage
/// (there is nothing to hold anyway; [`map_metrics`] reads the registry
/// fresh on every call, it doesn't accumulate a batch the way spans do).
async fn flush_metrics(
    client: &mut MetricsServiceClient<Channel>,
    registry: &Registry,
    resource: &Resource,
) {
    let request = map_metrics(registry, resource);
    if let Err(err) = client.export(request).await {
        tracing::warn!(error = %err, "OTLP metrics export failed");
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

    // `run_exporter` itself needs a real (or mock) collector -- exercised end
    // to end by `crates/proxy/tests/otlp_trace_e2e.rs`, not here. This
    // module's own tests stop at the pure mapping functions above, matching
    // this crate's existing split (e.g. `access_log::render` is unit-tested
    // here; the sink it writes through is exercised by whatever owns real
    // I/O).

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
}
