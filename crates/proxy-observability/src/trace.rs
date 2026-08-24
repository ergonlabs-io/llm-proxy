//! WP-51 increment 2 foundation: our own span model, plus W3C
//! `traceparent` parsing/serialization. Pure library code — nothing here is
//! wired into the request path yet, and nothing here is an OTLP wire type.
//! A later increment maps [`FinishedSpan`] to `opentelemetry.proto.trace`
//! (vendored in `proxy-api`, WP-51 increment 1); ground rule #2 keeps that
//! proto on the far side of the exporter, never handled by the data plane.
//!
//! # Two independent pieces
//!
//! - [`TraceContext`]: the 16-byte trace id / 8-byte span id / sampled flag
//!   that identifies where a span sits in a distributed trace, plus parsing
//!   and serializing the W3C `traceparent` header (<https://www.w3.org/TR/trace-context/>)
//!   so this proxy can participate in a trace it did not start.
//! - [`FinishedSpan`] / [`SpanSink`]: the record a completed span becomes,
//!   and the best-effort, non-blocking channel a worker uses to hand one to
//!   the control side. Neither performs I/O — exporting is a later step.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use rand::Rng;

/// A W3C trace context: which trace a span belongs to, this span's own id,
/// its parent (if any), and whether the trace is sampled.
///
/// `trace_id`/`span_id` are raw bytes, not hex strings — [`Self::parse_traceparent`]
/// decodes once at the edge and everything downstream works with fixed-size
/// arrays, matching how [`FinishedSpan`] carries them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceContext {
    pub trace_id: [u8; 16],
    pub span_id: [u8; 8],
    pub parent_span_id: Option<[u8; 8]>,
    pub sampled: bool,
}

impl TraceContext {
    /// Parse a W3C `traceparent` header value:
    /// `<version>-<trace-id>-<parent-id>-<trace-flags>`, e.g.
    /// `00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01`.
    ///
    /// Returns `None` on any malformation — the caller starts a fresh root
    /// span in that case ([`Self::new_root`]), so this never panics and
    /// never needs to distinguish *why* a header was rejected.
    ///
    /// Rejected, all with `None`:
    /// - wrong number of `-`-separated fields;
    /// - a version other than `00` (the only version this proxy speaks; the
    ///   spec reserves `ff` and allows future versions to add fields after
    ///   the ones defined here, but a `00`-shaped proxy has no way to know
    ///   what a later version's extra fields mean, so treating anything but
    ///   `00` as invalid is deliberately strict rather than partially
    ///   forward-compatible);
    /// - any field with the wrong hex length, or non-hex digits;
    /// - a trace id or span id that is all zero (the spec calls both
    ///   invalid — an all-zero trace id in particular is the sentinel for
    ///   "no trace context", not a real one).
    ///
    /// Rust note: this decodes over bytes, never `&str` indexing/slicing.
    /// `traceparent[i..j]` on a non-ASCII header can panic mid-way through a
    /// multi-byte UTF-8 character (`decode_hex_payload` in
    /// `proxy-config/src/lower.rs` documents the exact hazard) — checking
    /// `is_ascii()` up front, then working on `&[u8]`, rules that out
    /// entirely instead of trusting every call site to get the byte offsets
    /// right.
    pub fn parse_traceparent(header: &str) -> Option<Self> {
        if !header.is_ascii() {
            return None;
        }
        let bytes = header.as_bytes();

        let mut fields = bytes.split(|&b| b == b'-');
        let version = fields.next()?;
        let trace_id_hex = fields.next()?;
        let span_id_hex = fields.next()?;
        let flags_hex = fields.next()?;
        if fields.next().is_some() {
            // More than 4 fields. A later traceparent version is allowed to
            // append fields, but we only speak version 00 -- see the doc
            // comment above.
            return None;
        }

        if version != b"00" {
            return None;
        }

        let trace_id = decode_hex_array::<16>(trace_id_hex)?;
        let span_id = decode_hex_array::<8>(span_id_hex)?;
        let flags = decode_hex_array::<1>(flags_hex)?[0];

        if trace_id == [0u8; 16] || span_id == [0u8; 8] {
            return None;
        }

        Some(TraceContext {
            trace_id,
            span_id,
            parent_span_id: None,
            sampled: flags & 0x01 != 0,
        })
    }

    /// A fresh root span: random trace id and span id, no parent.
    ///
    /// Rust note: `rand::thread_rng()` is a thread-local CSPRNG handle, so
    /// this is cheap to call per request and needs no state threaded
    /// through (unlike `proxy-http::headers::splitmix64`, which is seeded
    /// explicitly so worker threads don't collide -- trace/span ids have no
    /// equivalent cross-worker uniqueness requirement, they only need to be
    /// unlikely to collide with any other span in the trace).
    pub fn new_root(sampled: bool) -> Self {
        TraceContext {
            trace_id: random_nonzero_array::<16>(),
            span_id: random_nonzero_array::<8>(),
            parent_span_id: None,
            sampled,
        }
    }

    /// A child of this context: same `trace_id` and `sampled` decision, a
    /// fresh span id, and `parent_span_id` set to this context's span id.
    pub fn child(&self) -> Self {
        TraceContext {
            trace_id: self.trace_id,
            span_id: random_nonzero_array::<8>(),
            parent_span_id: Some(self.span_id),
            sampled: self.sampled,
        }
    }

    /// Serialize back to the W3C wire form. Round-trips with
    /// [`Self::parse_traceparent`] (modulo `parent_span_id`, which
    /// `traceparent` has no field for -- see the module's test for exactly
    /// what "round-trip" means here).
    pub fn to_traceparent(&self) -> String {
        format!(
            "00-{}-{}-{:02x}",
            hex_encode(&self.trace_id),
            hex_encode(&self.span_id),
            if self.sampled { 1u8 } else { 0u8 }
        )
    }
}

/// Decode exactly `2 * N` ASCII hex digits into `[u8; N]`. `None` on wrong
/// length or a non-hex digit; never panics.
fn decode_hex_array<const N: usize>(hex: &[u8]) -> Option<[u8; N]> {
    if hex.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for i in 0..N {
        let hi = hex_digit(hex[i * 2])?;
        let lo = hex_digit(hex[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // `write!` to a `String` cannot fail.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// A random `[u8; N]` that is never all-zero (regenerated in the
/// astronomically unlikely case it is -- `2^(8N)` outcomes, one of which is
/// rejected).
fn random_nonzero_array<const N: usize>() -> [u8; N] {
    let mut rng = rand::thread_rng();
    loop {
        // Rust note: `Rng::fill` needs `[u8; N]: Fill`, which rand only
        // implements for a fixed list of concrete sizes -- not provable for
        // a generic `const N: usize`. Filling byte-by-byte with `Rng::gen`
        // (implemented for every integer type unconditionally) sidesteps
        // that and works for any `N`.
        let mut buf = [0u8; N];
        for b in buf.iter_mut() {
            *b = rng.gen();
        }
        if buf != [0u8; N] {
            return buf;
        }
    }
}

/// Where a span sits in a client/server call: which side of the wire it
/// represents. Matches OTLP's `SpanKind` naming for the two kinds this
/// proxy produces; a proxy request is always both -- the inbound leg is a
/// `Server` span, the outbound leg to the upstream cluster is a `Client`
/// span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanKind {
    Server,
    Client,
}

/// A span's outcome. Matches OTLP's three-value status (`Unset` is the
/// default -- most spans never set a status explicitly).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanStatus {
    Unset,
    Ok,
    Error,
}

/// A completed span, ready to hand to [`SpanSink::emit`].
///
/// Rust note: `start`/`end` are [`std::time::SystemTime`] (wall clock), not
/// [`std::time::Instant`] (monotonic). OTLP span timestamps are absolute
/// unix-nanos on the wire, and an `Instant` has no defined relationship to
/// the epoch -- it cannot be converted to one at all, only diffed against
/// another `Instant` from the same process. The exporter (a later step)
/// converts `SystemTime` to `u64` nanos since the epoch with
/// `duration_since(UNIX_EPOCH)`.
#[derive(Debug, Clone)]
pub struct FinishedSpan {
    pub context: TraceContext,
    pub name: String,
    pub kind: SpanKind,
    pub start: SystemTime,
    pub end: SystemTime,
    pub attributes: Vec<(&'static str, String)>,
    pub status: SpanStatus,
}

/// The worker-held handle for emitting finished spans to the control side.
///
/// Best-effort and non-blocking, per ADR-0005's "writes documented as
/// best-effort" requirement: a request must never wait on, or fail because
/// of, telemetry bookkeeping. [`Self::emit`] uses `try_send` and drops the
/// span (counting it) rather than applying backpressure to the caller.
///
/// Rust note: the data plane is `!Send` per ADR-0003, but that bounds
/// worker-local *runtime state* (connections, filter state) -- it says
/// nothing about a value merely being held inside a `!Send` future.
/// `tokio::sync::mpsc::Sender` is `Send + Clone` on its own, so cloning one
/// into worker-local code and sending across to a receiver the control
/// runtime owns is exactly the intended crossing point, the same shape
/// `StatsControl`/`Registry` and the access-log sink already use to move
/// data from worker to control.
#[derive(Clone)]
pub struct SpanSink {
    tx: tokio::sync::mpsc::Sender<FinishedSpan>,
    dropped: Arc<AtomicU64>,
}

impl SpanSink {
    /// Build a sink/receiver pair. `capacity` bounds how many finished spans
    /// can be buffered before [`Self::emit`] starts dropping; the control
    /// side owns the returned `Receiver` and is responsible for draining it
    /// (a later step -- the exporter).
    pub fn new(capacity: usize) -> (Self, tokio::sync::mpsc::Receiver<FinishedSpan>) {
        let (tx, rx) = tokio::sync::mpsc::channel(capacity);
        (
            SpanSink {
                tx,
                dropped: Arc::new(AtomicU64::new(0)),
            },
            rx,
        )
    }

    /// Hand a finished span to the control side. Never blocks, never
    /// `.await`s, never panics: a full or closed channel silently drops the
    /// span and increments [`Self::dropped_count`] instead. A full
    /// telemetry channel must never become request backpressure -- the same
    /// trade the access-log sink makes for a broken write destination.
    pub fn emit(&self, span: FinishedSpan) {
        if self.tx.try_send(span).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// How many spans have been dropped (channel full, or the control-side
    /// receiver already gone) since this sink's `Arc<AtomicU64>` was
    /// created. Shared across every clone of a given [`SpanSink`].
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- traceparent: parse / round-trip --------------------------------

    #[test]
    fn known_good_traceparent_parses_to_exact_bytes() {
        let ctx = TraceContext::parse_traceparent(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        )
        .expect("valid traceparent must parse");
        assert_eq!(
            ctx.trace_id,
            [
                0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e,
                0x47, 0x36
            ]
        );
        assert_eq!(
            ctx.span_id,
            [0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7]
        );
        assert!(ctx.sampled);
        assert_eq!(ctx.parent_span_id, None);
    }

    #[test]
    fn new_root_round_trips_through_traceparent() {
        let root = TraceContext::new_root(true);
        let parsed = TraceContext::parse_traceparent(&root.to_traceparent())
            .expect("a header we just serialized must parse");
        assert_eq!(parsed.trace_id, root.trace_id);
        assert_eq!(parsed.span_id, root.span_id);
        assert_eq!(parsed.sampled, root.sampled);
        // `traceparent` has no parent field -- a parsed header is always a
        // root as far as the wire format is concerned.
        assert_eq!(parsed.parent_span_id, None);
    }

    #[test]
    fn unsampled_round_trips_too() {
        let root = TraceContext::new_root(false);
        let parsed = TraceContext::parse_traceparent(&root.to_traceparent()).unwrap();
        assert!(!parsed.sampled);
    }

    // ---- traceparent: rejections -----------------------------------------

    #[test]
    fn wrong_version_is_rejected() {
        assert_eq!(
            TraceContext::parse_traceparent(
                "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
            ),
            None
        );
    }

    #[test]
    fn all_zero_trace_id_is_rejected() {
        assert_eq!(
            TraceContext::parse_traceparent(
                "00-00000000000000000000000000000000-00f067aa0ba902b7-01"
            ),
            None
        );
    }

    #[test]
    fn all_zero_span_id_is_rejected() {
        assert_eq!(
            TraceContext::parse_traceparent(
                "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01"
            ),
            None
        );
    }

    #[test]
    fn wrong_field_count_is_rejected() {
        assert_eq!(
            TraceContext::parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7"),
            None
        );
        assert_eq!(
            TraceContext::parse_traceparent(
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra"
            ),
            None
        );
    }

    #[test]
    fn non_hex_is_rejected() {
        assert_eq!(
            TraceContext::parse_traceparent(
                "00-zzf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
            ),
            None
        );
    }

    #[test]
    fn non_ascii_header_returns_none_not_panic() {
        // Pins the hazard called out in the doc comment: a non-ASCII header
        // must be rejected cleanly, never panic on a char-boundary slice.
        assert_eq!(TraceContext::parse_traceparent("00-über-bad-01"), None);
        assert_eq!(
            TraceContext::parse_traceparent(
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0€"
            ),
            None
        );
    }

    // ---- child ------------------------------------------------------------

    #[test]
    fn child_shares_trace_and_sampled_but_gets_a_new_span_id_and_parent() {
        let root = TraceContext::new_root(true);
        let child = root.child();
        assert_eq!(child.trace_id, root.trace_id);
        assert_eq!(child.sampled, root.sampled);
        assert_ne!(child.span_id, root.span_id);
        assert_eq!(child.parent_span_id, Some(root.span_id));
    }

    // ---- SpanSink -----------------------------------------------------

    #[test]
    fn emit_drops_past_capacity_without_blocking_and_counts_them() {
        let (sink, _rx) = SpanSink::new(1);
        let span = |name: &str| FinishedSpan {
            context: TraceContext::new_root(true),
            name: name.to_string(),
            kind: SpanKind::Server,
            start: SystemTime::now(),
            end: SystemTime::now(),
            attributes: Vec::new(),
            status: SpanStatus::Unset,
        };

        // No receiver drain -- the channel fills after the first send.
        sink.emit(span("a"));
        sink.emit(span("b"));
        sink.emit(span("c"));

        assert_eq!(
            sink.dropped_count(),
            2,
            "capacity 1, 3 emits, 0 drained -> 1 buffered, 2 dropped"
        );
        // Reaching this line at all is the "never blocked" assertion: emit
        // is synchronous and this test has no runtime driving the receiver.
    }

    #[test]
    fn dropped_count_is_shared_across_clones() {
        let (sink, _rx) = SpanSink::new(1);
        let clone = sink.clone();
        let span = || FinishedSpan {
            context: TraceContext::new_root(false),
            name: "x".to_string(),
            kind: SpanKind::Client,
            start: SystemTime::now(),
            end: SystemTime::now(),
            attributes: Vec::new(),
            status: SpanStatus::Unset,
        };

        sink.emit(span());
        clone.emit(span());
        clone.emit(span());

        assert_eq!(sink.dropped_count(), 2);
        assert_eq!(clone.dropped_count(), 2);
    }
}
