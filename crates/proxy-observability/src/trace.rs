//! Our own span model, plus W3C `traceparent` parsing and serialization. No
//! OTLP wire types live here. The exporter maps [`FinishedSpan`] to the OTLP
//! proto on the far side, per AGENTS.md invariant 2.
//!
//! - [`TraceContext`]: trace id, span id and sampled flag, plus the W3C
//!   `traceparent` header (<https://www.w3.org/TR/trace-context/>).
//! - [`FinishedSpan`] and [`SpanSink`]: a completed span, and the non-blocking
//!   channel a worker uses to hand it to the control side. Neither does I/O.

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
    /// Returns `None` on any malformation, so the caller starts a fresh root
    /// span ([`Self::new_root`]). Rejected:
    /// - a wrong number of `-`-separated fields;
    /// - a version other than `00`. This is deliberately strict, since a `00`
    ///   proxy cannot know what a later version's extra fields mean;
    /// - a field with the wrong hex length or non-hex digits;
    /// - an all-zero trace id or span id, which the spec calls invalid.
    ///
    /// Rust note: this decodes over bytes, never `&str` slices. Slicing a
    /// non-ASCII header can panic mid-character, so `is_ascii()` is checked first.
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
    /// Rust note: `thread_rng()` is a cheap thread-local handle, so no state is
    /// threaded through. IDs only need to be unlikely to collide.
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

/// Which side of the wire a span represents. A proxy request yields a `Server`
/// span for the inbound leg and a `Client` span for the upstream leg.
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
/// Rust note: `start` and `end` are [`std::time::SystemTime`], not `Instant`.
/// OTLP needs absolute epoch timestamps, and an `Instant` cannot be converted
/// to one.
#[derive(Debug, Clone)]
pub struct FinishedSpan {
    pub context: TraceContext,
    pub name: String,
    pub kind: SpanKind,
    pub start: SystemTime,
    pub end: SystemTime,
    pub attributes: Vec<(&'static str, String)>,
    /// Integer-valued attributes, exported as OTLP `int_value` rather than
    /// strings, for semconv attributes typed `int` (the `gen_ai.usage.*`
    /// token counts).
    pub int_attributes: Vec<(&'static str, i64)>,
    pub status: SpanStatus,
}

/// The worker-held handle for emitting finished spans to the control side.
///
/// Best-effort and non-blocking (ADR-0005). [`Self::emit`] uses `try_send` and
/// counts a dropped span rather than applying backpressure to a request.
///
/// Rust note: the data plane is `!Send` (ADR-0003), but a `Sender` is `Send` and
/// `Clone` on its own, so it can cross from worker to control.
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

    /// A read-only handle onto the same drop counter, for the OTLP exporter to
    /// republish as [`crate::stats::instruments::OTEL_SPANS_DROPPED`]. Dropped
    /// spans never reach the backend, so this aggregate is the only loss signal
    /// (`docs/telemetry-design.md` §5.5).
    pub fn drop_counter(&self) -> SpanDropCounter {
        SpanDropCounter(Arc::clone(&self.dropped))
    }
}

/// Read-only view of a [`SpanSink`]'s cumulative drop count. See
/// [`SpanSink::drop_counter`] for why this is its own type rather than a bare
/// `Arc<AtomicU64>`.
///
/// `Clone` on purpose, and cheap (an `Arc` refcount bump): the metric exporter
/// holds one of these for the life of the process while every worker holds its
/// own [`SpanSink`] clone of the same underlying counter.
#[derive(Clone, Debug)]
pub struct SpanDropCounter(Arc<AtomicU64>);

impl SpanDropCounter {
    /// The process-cumulative drop count. Monotonic within a process lifetime
    /// and zero again after a restart -- which is exactly why the exporter
    /// publishes it as a *delta* onto a registry counter rather than as a set
    /// value (see [`crate::stats::instruments::OTEL_SPANS_DROPPED`]).
    pub fn load(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
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
            int_attributes: Vec::new(),
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
            int_attributes: Vec::new(),
            status: SpanStatus::Unset,
        };

        sink.emit(span());
        clone.emit(span());
        clone.emit(span());

        assert_eq!(sink.dropped_count(), 2);
        assert_eq!(clone.dropped_count(), 2);
    }
}
