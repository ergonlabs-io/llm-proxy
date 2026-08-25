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

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc::Receiver;
use tonic::transport::{Channel, Endpoint};

use proxy_api::opentelemetry::proto::collector::trace::v1::{
    trace_service_client::TraceServiceClient, ExportTraceServiceRequest,
};
use proxy_api::opentelemetry::proto::common::v1::{any_value, AnyValue, KeyValue};
use proxy_api::opentelemetry::proto::resource::v1::Resource;
use proxy_api::opentelemetry::proto::trace::v1::{
    span::SpanKind as OtlpSpanKind, status::StatusCode as OtlpStatusCode, ResourceSpans,
    ScopeSpans, Span, Status,
};

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
    let mut client = TraceServiceClient::new(channel);
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
                        flush(&mut client, &resource, &mut batch).await;
                        return;
                    }
                }
            }
            _ = ticker.tick() => {
                flush(&mut client, &resource, &mut batch).await;
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
}
