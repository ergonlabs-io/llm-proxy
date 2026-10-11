//! The OTLP/gRPC trace exporter -- drains a
//! [`crate::trace::SpanSink`]'s [`Receiver`](tokio::sync::mpsc::Receiver) and
//! ships batches of [`FinishedSpan`] to a real collector.
//!
//! This is the one module in the data-plane-adjacent crates that names a
//! generated OTLP proto (`proxy_api::opentelemetry`). AGENTS.md invariant 2
//! ("protos never escape `proxy-config`/`proxy-xds`") is about *Envoy
//! config* protos never reaching request-handling code -- see `ir.rs`'s own
//! module doc for why that boundary matters (strict-mode field coverage,
//! IR as the one API surface every workstream codes against). OTLP export is a
//! different protocol serving a different purpose: [`run_trace_exporter`] and
//! [`run_metric_exporter`] run entirely on the CONTROL runtime
//! (`crates/proxy/src/main.rs`'s `run_serve`, next to the config-publisher
//! tasks), never touch a request, and their only job is to hand
//! already-finished, already-owned [`FinishedSpan`] values (or a read-only
//! snapshot of the stats registry) to a collector over the wire. Nothing here
//! is parsed out of, or fed back into, the [`proxy_config::ir`] the data plane
//! actually runs on.
//!
//! Four pieces:
//! - [`map_span`]: pure `FinishedSpan -> proto Span` conversion, unit-tested
//!   on its own (no network).
//! - [`map_metrics`]: pure `Registry -> proto ExportMetricsServiceRequest`
//!   conversion, same split.
//! - [`run_trace_exporter`]: the span batching loop. Owns the `Receiver` end
//!   of a `SpanSink` for its whole life; returns once every `SpanSink` clone
//!   has been dropped (workers gone) and the last batch is flushed.
//! - [`run_metric_exporter`]: the registry snapshot loop. **Independent of
//!   the trace exporter** -- its own task, its own ticker, its own deadline,
//!   and no dependency on a `SpanSink` existing at all.
//!
//! # Why traces and metrics are two exporters, not one
//!
//! `docs/telemetry-design.md` §5.3 requires metric export to be configurable
//! and schedulable independently of trace sampling. Before this split, both
//! signals shared one task and one 5s ticker, which made three of the design
//! doc's requirements unsatisfiable:
//!
//! - Metrics could not be exported at all unless tracing was configured, since
//!   the only `MetricsServiceClient` was constructed inside the task spawned
//!   for a `TracingConfig`.
//! - A slow or unreachable *trace* RPC held the single `flush().await` open,
//!   so the metric snapshot on the same tick could not proceed.
//! - There was no deadline on either RPC at all, so a connection that
//!   established and then went silent held the task's `.await` open forever.
//!
//! Each exporter now counts its own failures into
//! [`crate::stats::instruments::OTEL_EXPORT_FAILURES`] under a finite `signal`
//! label, so a collector outage is visible as a metric rather than only as a
//! gap in someone else's dashboard. Span losses -- both queue drops and
//! discarded batches -- ride in `llmproxy_otel_spans_dropped`, published by
//! the TRACE exporter (the path that causes them), so a Prometheus-only
//! deployment with no OTLP metric export still reports them. Each exporter
//! also enforces its own per-RPC deadline (`MetricsExportConfig::
//! export_deadline`, `TracingConfig::export_deadline`), so a collector that
//! accepts a connection and then goes silent costs one bounded timeout per
//! attempt instead of parking a task forever.

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

/// Flush whichever comes first: this many buffered spans, or
/// [`BATCH_INTERVAL`] elapsing with at least one span buffered. Matches the
/// module brief's "batches on an interval or a max-batch size" -- neither
/// bound alone is right: a quiet proxy would otherwise hold a handful of
/// spans indefinitely, and a busy one would otherwise buffer unboundedly
/// between ticks.
const MAX_BATCH: usize = 512;
const BATCH_INTERVAL: Duration = Duration::from_secs(5);

/// Upper bound on `TracingConfig::export_deadline`, exported so
/// `proxy-config`'s loader can validate against the SAME number this module
/// documents, rather than a copy that can drift. The trace batch interval is a
/// fixed constant (`BATCH_INTERVAL`; tracing config exposes sampling, not
/// cadence -- see `MetricsExportConfig::export_interval` for why the metric
/// side did get a configurable one), so this cap is a sanity bound against
/// absurd values, not a cross-field ordering rule: a deadline longer than a
/// full batch cycle would let a wedged export hold every batch in memory
/// across multiple cycles before being abandoned.
pub const TRACE_EXPORT_DEADLINE_MAX: Duration = Duration::from_secs(60);

/// Convert a [`FinishedSpan`] into the OTLP wire type. Pure -- no I/O, so
/// this is unit-tested directly rather than only through
/// [`run_trace_exporter`]'s network path.
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
/// (mirroring [`map_span`]) rather than only through
/// [`run_metric_exporter`]'s network path.
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

/// The span batching export loop. Runs until `rx` is closed (every clone of
/// the [`SpanSink`](crate::trace::SpanSink) that fed it has been dropped) and
/// its last batch is flushed -- `crates/proxy/src/main.rs` spawns this on the
/// control runtime only when `snapshot.tracing` is `Some`; tracing-off means
/// this function is never called at all, matching the module brief's "zero cost
/// when off".
///
/// **No longer exports metrics.** See the module doc's "Why traces and metrics
/// are two exporters" section; [`run_metric_exporter`] owns that now and runs
/// whether or not this function exists.
///
/// # Failure handling
///
/// Export failure (a connect error, the collector rejecting the batch, or a
/// deadline expiry -- `tonic::Status` covers the first two uniformly, and
/// `tokio::time::timeout` converts the third into this same match arm) logs,
/// counts itself into `OTEL_EXPORT_FAILURES` under `signal="traces"`, counts
/// the discarded batch's spans into the drop ledger, and drops the batch.
/// Telemetry must never take the proxy down or fail a request over an
/// unreachable collector; see `trace::SpanSink::emit` for the same trade one
/// layer up (a full channel drops instead of blocking a request).
///
/// `export_deadline` bounds the RPC. Without it (the pre-review shape) a
/// collector that accepted the connection and went silent parked this task's
/// `.await` forever -- every later batch buffered, `MAX_BATCH` became the only
/// further bound, and the sink behind it filled and dropped -- a stall that
/// looked like telemetry degradation but was really an unbounded export. The
/// deadline makes each hung attempt cost exactly one timeout, and the next
/// tick's batch -- carrying everything served since -- still gets its chance.
/// `crates/proxy/tests/otlp_trace_e2e.rs` pins this on the real binary against
/// a collector that hangs its first export and answers the rest.
///
/// Reconnection is deliberately NOT hand-rolled: `Endpoint::connect_lazy` builds
/// a `Channel` that establishes its connection lazily on first use and
/// reconnects on its own for every subsequent call through tower's built-in
/// retry-connect behavior, so "try again next tick" falls out of just calling
/// `export` again -- there is no retry loop here holding a batch hostage while a
/// collector is down.
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
                            flush(&mut client, &resource, &mut batch, &registry, &failures, export_deadline).await;
                        }
                    }
                    None => {
                        // Every `SpanSink` clone is gone -- drain whatever's
                        // left, then this task has nothing further to do. This
                        // is the only "final flush on shutdown" in this
                        // module: metrics are not involved, because
                        // `run_metric_exporter` has its own independent
                        // lifecycle and its own deadline.
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

/// The registry snapshot export loop. **Independent of
/// [`run_trace_exporter`] in every dimension that matters**: it is a separate
/// task, it is spawned whenever `snapshot.metrics` is `Some` whether or not
/// tracing is configured, its interval and deadline are its own
/// (`MetricsExportConfig`'s), and its only shared state with the trace path is
/// the read-only [`Registry`].
///
/// [`shutdown`] is how this task ends. There is no channel to close here (it
/// consumes no events, only time), so without an explicit signal it would run
/// until the runtime dropped it -- and the process's own shutdown sequence
/// (`proxy_core::runtime::graceful_shutdown`) is what a caller passes this. A
/// receiver that fires mid-sleep still gets one last snapshot out: a metric
/// snapshot is cheap, cumulative, and the natural last word on a run.
///
/// # Why there is no retry, and no disk spool
///
/// Design doc §5.3: "Span queues and batches are bounded... No disk spool is
/// required inside the proxy for operational signals", and a failed snapshot
/// "can be superseded by a later snapshot" because the registry is cumulative
/// and never cleared. Retaining a failed snapshot to retry it would be
/// strictly worse: it would either hold unbounded memory across a long outage
/// or need exactly the spool this design declines to build, in exchange for
/// re-sending data the next tick already contains. The failure is counted
/// instead, so the gap is visible rather than silent.
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
    // Same reasoning as the trace exporter's ticker, and here it is load-bearing
    // rather than merely tidy: an export that runs up to `export_deadline`
    // must not produce a burst of catch-up ticks afterwards. `Delay` makes the
    // next tick `export_interval` after the previous one *finished*.
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

/// Pre-resolved handles for the two failure counters this module writes, one
/// per signal, plus the span-drop republisher.
///
/// Built once at boot by [`ExportCounters::resolve`] against the one
/// `StatsControl` in the process, and then only *read* through. That matters
/// because both exporter tasks call `Registry::incr`, which needs a
/// [`WorkerId`](crate::stats::WorkerId) -- a shard index that is meaningful
/// for a worker and arbitrary for a control-side task. Using `WorkerId(0)` is
/// the honest encoding of "this is not a worker's increment": the value lands
/// in one shard and every read sums across all of them, so which shard it
/// lands in cannot change what any renderer or exporter reports. It is
/// documented here rather than left as a bare `WorkerId(0)` at each call site
/// so the next reader does not have to re-derive why it is safe.
///
/// Only two failure series exist for the life of the process, because `signal`
/// has exactly two values ([`EXPORT_SIGNAL_TRACES`],
/// [`EXPORT_SIGNAL_METRICS`]) and resolution happens once. Neither task
/// resolves anything at runtime.
///
/// This is also the SOLE publisher of `llmproxy_otel_spans_dropped`, on
/// purpose. The review found that while the METRIC exporter held that job, a
/// tracing deployment WITHOUT OTLP metric export (Prometheus-scrape-only, the
/// majority of deployments) reported zero span drops forever -- the one signal
/// measuring the trace pipeline's losses was gated on a different pipeline's
/// existence. Both drop sources live in the trace path (queue drops from
/// `SpanSink::emit`, batch drops from failed exports), so the trace exporter
/// publishes both, whatever the metric exporter is doing.
#[derive(Clone)]
pub struct ExportCounters {
    trace_failures: Handle,
    spans_dropped: Handle,
    /// Combined view of both trace-path drop sources. `Arc` because the sink
    /// owns the queue counter and this reads it; the batch counter is written
    /// by whoever flushes a failed export.
    drops: Arc<DropLedger>,
    /// Last published combined total. Publish only its increase to the
    /// monotonic registry counter.
    ///
    /// Rust note: the shared atomic keeps references to this state `Sync`
    /// across exporter awaits; a `Cell` would not. There is one publisher.
    last_republished: Arc<AtomicU64>,
}

/// The two trace-path span-loss sources, summed by [`ExportCounters`].
pub struct DropLedger {
    /// Queue drops: the sink's own cumulative counter, shared with every
    /// `SpanSink` clone (channel full, or receiver gone). `None` when tracing
    /// is unconfigured -- there is no sink, hence no queue drops, and the
    /// ledger must not invent any.
    queue: Option<SpanDropCounter>,
    /// Batch drops: spans discarded by a failed or timed-out export. Counted
    /// at failure, in the one place that knows the batch's size, rather than
    /// reconstructed later -- design doc §5.5's "aggregate drop counters are
    /// the dependable signal" applies verbatim: the spans that could not be
    /// exported are exactly the ones no per-span event could report.
    batch: AtomicU64,
}

impl DropLedger {
    fn total(&self) -> u64 {
        let queue = self.queue.as_ref().map_or(0, SpanDropCounter::load);
        queue.wrapping_add(self.batch.load(Ordering::Relaxed))
    }
}

impl ExportCounters {
    /// Resolve the trace-side handles, adopting the sink's drop counter when
    /// tracing is configured (`Some`) and none when it is not.
    ///
    /// The SERIES are resolved unconditionally either way, so a dashboard sees
    /// `signal="traces"` and `llmproxy_otel_spans_dropped` from the very first
    /// scrape of a tracing-off process and can tell "zero failures / zero
    /// drops" from "not instrumented" -- the design doc §5.5 requirement the
    /// review round leaned on. The LEDGER, though, is honest about `None`:
    /// with no `SpanSink` there are no queue drops, no exporter to drop
    /// batches, and a series that claims otherwise would be lying. `None`
    /// therefore publishes nothing, and the zero the dashboard sees is the
    /// truth.
    ///
    /// Panics are not a concern: every attribute set here is a
    /// `(&'static str, &'static str)` literal, so `Registry`'s attribute-key
    /// validation (which is designed to catch caller typos) has nothing to
    /// catch.
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

    /// Count one failed trace export AND the spans the dropped batch carried.
    /// The failure lands in the registry immediately; the drop lands in the
    /// ledger and is published by the next [`Self::publish_drops`] -- same tick
    /// for the batch-full path, next tick at worst for the interval path,
    /// which is bounded by `BATCH_INTERVAL` and costs nothing a scrape
    /// interval would not swamp anyway.
    fn record_trace_failure(&self, registry: &Registry, batch_spans: u64) {
        registry.incr(WorkerId(0), self.trace_failures, 1);
        self.drops.batch.fetch_add(batch_spans, Ordering::Relaxed);
    }

    /// Move the delta of the combined drop ledger into `spans_dropped`. Called
    /// after every flush, successful or not, so queue drops accumulated since
    /// the last tick are reflected without a failed export being a
    /// precondition for visibility. Cheap when nothing changed: one load and
    /// one compare.
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
/// Split out from [`ExportCounters`] because the two exporters need
/// *different* subsets, and handing the metric exporter the trace failure
/// handle would invite incrementing the wrong one. Span drops are NOT here:
/// they are trace-path facts published by the trace exporter itself --
/// gating them on metric export is exactly the underreporting bug [`ExportCounters`]'s
/// doc records.
pub struct MetricExportHealth {
    failures: Handle,
}

impl MetricExportHealth {
    /// Resolve the metric-side failure handle. Call once, control side, at
    /// boot, and UNCONDITIONALLY -- even with no metric export configured, so
    /// `llmproxy_otel_export_failures{signal="metrics"}` exists from the very
    /// first scrape and a dashboard can tell "zero failures" from "not
    /// instrumented" (`tests/otlp_trace_e2e.rs`'s
    /// `prometheus_scrape_works_with_no_otlp_configured` pins that).
    pub fn resolve(control: &StatsControl) -> Self {
        MetricExportHealth {
            failures: control.resolve(
                &instruments::OTEL_EXPORT_FAILURES,
                &[("signal", instruments::EXPORT_SIGNAL_METRICS)],
            ),
        }
    }

    /// Count one failed metric export. See [`ExportCounters`]'s doc for why
    /// `WorkerId(0)` is the correct shard for a control-side increment.
    fn record_metric_failure(&self, registry: &Registry) {
        registry.incr(WorkerId(0), self.failures, 1);
    }
}

/// Build a lazily-connecting [`TraceServiceClient`], or `None` (after logging)
/// if the endpoint string cannot be parsed at all.
///
/// Rust note: this is the same "log once and give up" shape the pre-split
/// single exporter had inline, factored out because both exporters now need
/// the identical logic and the metric variant additionally needs its own
/// client type. An endpoint string that can't be parsed into an `Endpoint`
/// (`TracingConfig::otlp_endpoint` / `MetricsExportConfig::otlp_endpoint` are
/// validated non-empty at config-lowering time, but not that they're
/// well-formed URIs -- see those fields' docs) can never succeed on any later
/// tick either, so there is nothing to reconnect: every event emitted from here
/// on is dropped rather than held anywhere.
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

/// The metric-path twin of [`trace_client`]. Separate `Endpoint` rather than a
/// `clone()` of the trace one, so the two exporters hold genuinely independent
/// connection state: a channel wedged behind a half-open trace connection
/// cannot also stall the metric export, which is the same "no shared
/// congestible resource" property `docs/telemetry-design.md` §4 asks for between
/// operational export and content capture, applied here between the two
/// operational signals.
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

/// Export `batch` (if non-empty) and clear it, regardless of outcome -- see
/// [`run_trace_exporter`]'s doc on why a failure logs and drops rather than
/// retaining the batch for another attempt. A failed or timed-out batch is
/// ALSO counted into both trace self-instruments: the failure under
/// `signal="traces"`, and every span it discarded into the drop ledger that
/// `publish_drops` moves into `llmproxy_otel_spans_dropped` -- the review
/// flagged counting the failure while losing the batch size as underreporting,
/// and a "1 failure" with no attached span count cannot answer the only
/// question an operator asks it.
async fn flush(
    client: &mut TraceServiceClient<Channel>,
    resource: &Resource,
    batch: &mut Vec<FinishedSpan>,
    registry: &Registry,
    failures: &ExportCounters,
    export_deadline: Duration,
) {
    // Publish BEFORE the empty-batch return, not after it: queue drops accrue
    // whether or not there is anything to export, and a quiet-but-dropping
    // pipeline is precisely when an operator most needs the counter live. The
    // call is a load-compare-store against zero delta when nothing changed.
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
    // Drop the batch either way -- `Vec::clear` after the `.await`, not
    // before: `batch` (the caller's buffer) has to stay populated for the
    // `spans`/`request` build above regardless of what `export` returns.
    //
    // The deadline bounds a collector that ACCEPTS the connection and then
    // stops responding -- exactly the hazard the metric exporter's deadline
    // exists for, and the review correctly refused to let traces keep running
    // without one: without it, the first hung `export` parks this task's
    // `.await` forever, every later batch buffers to `MAX_BATCH`, and the sink
    // behind it fills and starts dropping -- an unbounded stall presented as
    // best-effort telemetry. `ExportTraceServiceRequest` is moved into the
    // timeout future and dropped with it on expiry; tonic's own docs say a
    // cancelled request is safe, its outcome simply unknown to the client.
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
            // A timed-out batch is exactly as lost as a rejected one, and the
            // spans it carried were discarded either way -- count both, here
            // and in `ExportCounters::record_trace_failure`, never just the
            // failure alone.
            failures.record_trace_failure(registry, span_count as u64);
            tracing::warn!(
                deadline_ms = export_deadline.as_millis() as u64,
                spans = span_count,
                "OTLP trace export timed out; batch dropped"
            );
        }
    }
    batch.clear();
    // And publish again, now that this flush's own batch drops (if any) are
    // in the ledger: a failed export's losses become scrape-visible in the
    // same moment they happen, not one `BATCH_INTERVAL` later. The entry call
    // above covers the case where THIS flush records nothing but the queue
    // counter grew; this one covers the reverse. Together they make "drops
    // recorded, registry not yet told" impossible at any return point of this
    // function, at the cost of one no-op delta check.
    failures.publish_drops(registry);
}

/// Export the registry's current cumulative state, bounded by `deadline`.
///
/// Same best-effort contract as [`flush`] -- a failure logs, counts itself, and
/// moves on. There is nothing to hold hostage either way: [`map_metrics`] reads
/// the registry fresh on every call, it does not accumulate a batch.
///
/// The registry is **not** cleared on failure, deliberately. Design doc §5.3:
/// "An unsuccessful snapshot can be superseded by a later snapshot; interval
/// histograms must not be cleared on failed export." This registry only ever
/// holds cumulative values in the first place, so there is no interval state
/// that could be lost by not clearing -- but the next snapshot would report the
/// same cumulative totals regardless, and that is the property being relied on.
async fn flush_metrics(
    client: &mut MetricsServiceClient<Channel>,
    registry: &Registry,
    resource: &Resource,
    deadline: Duration,
    health: &MetricExportHealth,
) {
    let request = map_metrics(registry, resource);
    // The deadline is the only thing bounding this `.await`. `connect_lazy`
    // reconnects on its own, but a connection that establishes and then stops
    // responding would otherwise park this task forever, taking every later
    // tick with it.
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

    // `run_trace_exporter`/`run_metric_exporter` themselves need a real (or
    // mock) collector -- exercised end
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

    // ---- self-instrumentation: failure counters and the drop ledger -------

    /// Both failure series must exist as soon as both resolver types have run,
    /// and carry distinct `signal` values. Two resolved series with the same
    /// value would silently collapse into one -- an operator could not tell a
    /// trace outage from a metric one, which is the entire reason the `signal`
    /// label exists.
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

    /// Resolving the same counters twice (a boot-time resolve plus a reload
    /// path, say) must not grow a second pair of series. `Registry`'s dedup is
    /// keyed on `(instrument, attrs)`, so this is really a regression test on
    /// the values above being distinct-but-stable rather than freshly minted.
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

    /// The review's P2 in its full form: a Prometheus-only deployment (tracing
    /// ON, OTLP metric export OFF) must still see span drops. The trace
    /// exporter publishes the ledger, so this needs no metric exporter at all
    /// -- but it DOES need the series to exist, which is why `resolve` takes
    /// the `Option`: the trace side resolves unconditionally from `main.rs`,
    /// and this test pins that a `None` sink (the tracing-off shape) still
    /// produces both series, publishes nothing, and reports zero.
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

    /// The ledger is a DELTA publisher, not a running-total setter: the source
    /// counters are cumulative over the process's life and the registry handle
    /// they feed must only ever see increases, so a publish that observes no
    /// new drops must add nothing (rather than adding the running total again
    /// and inflating the series without bound).
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

    /// The review's P2: a failed trace export counted the failure but dropped
    /// the batch's span count on the floor -- "1 failure" with no attached
    /// loss total cannot answer the only question an operator asks it. The
    /// ledger must carry the batch's spans too, and both must land in the
    /// registry after one publish.
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

    /// Queue drops and batch drops must SUM, not overwrite: both are real
    /// losses on the same pipeline, and an operator reading
    /// `llmproxy_otel_spans_dropped` needs the total, not whichever happened
    /// to be written last.
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
        // Both signals resolved, so "the other one stayed at zero" is a real
        // assertion about this counter rather than an artifact of the series
        // not existing yet -- which is the state a tracing-off process is in.
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

    /// Read the current `llmproxy_otel_spans_dropped` total out of the
    /// registry. Resolving is idempotent, so the test can resolve on every
    /// call to read the value at that moment without adding a series.
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
