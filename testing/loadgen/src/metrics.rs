//! Per-stream result recording and aggregation.
//!
//! Concurrency note (see crate-level constraint on avoiding shared-mutex
//! contention at load): every stream task computes its own
//! [`StreamResult`] locally and hands it to a single collector task over an
//! `mpsc` channel (see `driver.rs`). The collector is the sole owner of the
//! [`Aggregator`]'s histograms -- there is no `Mutex`, and no lock is ever
//! held across an `.await`, because nothing is ever shared: results are
//! *moved* to their one owner instead.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;
use serde::Serialize;

/// How one stream ended. Kept as its own type (not folded into an `Ok`
/// path) because a nonzero error rate must be surfaced loudly rather than
/// averaged away -- see [`Aggregator::error_rate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Success,
    HttpError(u16),
    TransportError,
    Timeout,
}

/// Everything measured about one stream. Built by `driver.rs` as the stream
/// runs and sent, whole, to the aggregator once it ends.
#[derive(Debug, Clone)]
pub struct StreamResult {
    /// The stream's *intended* start time -- for closed-loop this equals
    /// `send_start`; for open-loop it is the fixed-rate schedule slot, which
    /// can precede `send_start` if the driver fell behind. This is the
    /// coordinated-omission correction: every "from_scheduled" duration
    /// below is measured against this, not against when the request
    /// actually went out, so driver backlog shows up as inflated latency
    /// instead of being silently absorbed.
    pub scheduled_start: Instant,
    /// When the request was actually dispatched (connect started).
    pub send_start: Instant,
    pub outcome: Outcome,
    /// Time to first content-bearing SSE frame, `None` if none ever arrived
    /// (error, timeout, or a `--no-stream` run).
    pub ttft_from_scheduled: Option<Duration>,
    pub ttft_from_send: Option<Duration>,
    pub total_from_scheduled: Duration,
    pub total_from_send: Duration,
    /// Gaps between successive content-delta frames within this one stream.
    /// Small (bounded by tokens-per-response), so collecting them per
    /// stream and merging into the aggregator's histogram on receipt is
    /// cheap -- no per-frame allocation happens on the hot path, only a
    /// `Duration` push per token.
    pub inter_token_gaps: Vec<Duration>,
    pub tokens_received: u64,
    pub bytes_received: u64,
}

/// One run's fully aggregated stats, ready to serialize.
#[derive(Debug, Clone, Serialize)]
pub struct RunSummary {
    pub streams_started: u64,
    pub streams_counted: u64,
    pub warmup_excluded: u64,
    pub success: u64,
    pub http_errors: BTreeMap<u16, u64>,
    pub transport_errors: u64,
    pub timeouts: u64,
    pub error_rate: f64,
    pub tokens_received: u64,
    pub bytes_received: u64,
    pub ttft_from_scheduled_us: Option<Percentiles>,
    pub ttft_from_send_us: Option<Percentiles>,
    pub inter_token_us: Option<Percentiles>,
    pub total_from_scheduled_us: Option<Percentiles>,
    pub total_from_send_us: Option<Percentiles>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Percentiles {
    pub min: u64,
    pub p50: u64,
    pub p90: u64,
    pub p99: u64,
    pub p999: u64,
    pub max: u64,
    pub mean: f64,
    pub count: u64,
}

fn percentiles(h: &Histogram<u64>) -> Percentiles {
    Percentiles {
        min: h.min(),
        p50: h.value_at_quantile(0.50),
        p90: h.value_at_quantile(0.90),
        p99: h.value_at_quantile(0.99),
        p999: h.value_at_quantile(0.999),
        max: h.max(),
        mean: h.mean(),
        count: h.len(),
    }
}

/// Owns every histogram for a run. Not `Clone`/`Send`-shared -- see the
/// module doc: one collector task owns this exclusively.
pub struct Aggregator {
    warmup_end: Instant,
    streams_started: u64,
    warmup_excluded: u64,
    success: u64,
    http_errors: BTreeMap<u16, u64>,
    transport_errors: u64,
    timeouts: u64,
    tokens_received: u64,
    bytes_received: u64,
    ttft_from_scheduled: Histogram<u64>,
    ttft_from_send: Histogram<u64>,
    inter_token: Histogram<u64>,
    total_from_scheduled: Histogram<u64>,
    total_from_send: Histogram<u64>,
}

impl Aggregator {
    /// `warmup_end`: results whose `scheduled_start` is before this are
    /// counted towards `streams_started`/`warmup_excluded` but excluded
    /// from every histogram and error count, per `--warmup`.
    pub fn new(warmup_end: Instant) -> Self {
        // Rust note: `new_with_bounds(lowest, highest, sig_figs)` -- these
        // histograms record microsecond durations; 1us..1hr covers every
        // latency this driver could plausibly see (a stalled/hung stream
        // included) without the histogram growing unbounded.
        let make = || {
            Histogram::<u64>::new_with_bounds(1, 3_600_000_000, 3).expect("valid histogram bounds")
        };
        Self {
            warmup_end,
            streams_started: 0,
            warmup_excluded: 0,
            success: 0,
            http_errors: BTreeMap::new(),
            transport_errors: 0,
            timeouts: 0,
            tokens_received: 0,
            bytes_received: 0,
            ttft_from_scheduled: make(),
            ttft_from_send: make(),
            inter_token: make(),
            total_from_scheduled: make(),
            total_from_send: make(),
        }
    }

    pub fn record(&mut self, result: StreamResult) {
        self.streams_started += 1;
        if result.scheduled_start < self.warmup_end {
            self.warmup_excluded += 1;
            return;
        }

        match result.outcome {
            Outcome::Success => self.success += 1,
            Outcome::HttpError(status) => {
                *self.http_errors.entry(status).or_insert(0) += 1;
            }
            Outcome::TransportError => self.transport_errors += 1,
            Outcome::Timeout => self.timeouts += 1,
        }

        self.tokens_received += result.tokens_received;
        self.bytes_received += result.bytes_received;

        if let Some(ttft) = result.ttft_from_scheduled {
            record_duration(&mut self.ttft_from_scheduled, ttft);
        }
        if let Some(ttft) = result.ttft_from_send {
            record_duration(&mut self.ttft_from_send, ttft);
        }
        for gap in &result.inter_token_gaps {
            record_duration(&mut self.inter_token, *gap);
        }
        record_duration(&mut self.total_from_scheduled, result.total_from_scheduled);
        record_duration(&mut self.total_from_send, result.total_from_send);
    }

    pub fn finish(self) -> RunSummary {
        let streams_counted = self.streams_started - self.warmup_excluded;
        let errored =
            self.http_errors.values().sum::<u64>() + self.transport_errors + self.timeouts;
        let error_rate = if streams_counted == 0 {
            0.0
        } else {
            errored as f64 / streams_counted as f64
        };
        let non_empty = |h: &Histogram<u64>| (!h.is_empty()).then(|| percentiles(h));
        RunSummary {
            streams_started: self.streams_started,
            streams_counted,
            warmup_excluded: self.warmup_excluded,
            success: self.success,
            http_errors: self.http_errors,
            transport_errors: self.transport_errors,
            timeouts: self.timeouts,
            error_rate,
            tokens_received: self.tokens_received,
            bytes_received: self.bytes_received,
            ttft_from_scheduled_us: non_empty(&self.ttft_from_scheduled),
            ttft_from_send_us: non_empty(&self.ttft_from_send),
            inter_token_us: non_empty(&self.inter_token),
            total_from_scheduled_us: non_empty(&self.total_from_scheduled),
            total_from_send_us: non_empty(&self.total_from_send),
        }
    }
}

fn record_duration(h: &mut Histogram<u64>, d: Duration) {
    // Saturate rather than panic on an implausibly large duration (e.g. a
    // clock jump); losing precision on an outlier that big is preferable to
    // crashing a long-running load test.
    let us = d.as_micros().try_into().unwrap_or(u64::MAX);
    let us = us.max(1).min(h.high());
    let _ = h.record(us);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// hdrhistogram trades a small, bounded relative error for O(1)
    /// recording -- assert "within 1%", not bit-exact.
    fn assert_close(actual: u64, expected: u64) {
        let diff = actual.abs_diff(expected);
        assert!(
            diff <= expected / 100 + 1,
            "expected {actual} to be within 1% of {expected}"
        );
    }

    fn base_result(scheduled_start: Instant, send_start: Instant) -> StreamResult {
        StreamResult {
            scheduled_start,
            send_start,
            outcome: Outcome::Success,
            ttft_from_scheduled: Some(Duration::from_millis(10)),
            ttft_from_send: Some(Duration::from_millis(5)),
            total_from_scheduled: Duration::from_millis(50),
            total_from_send: Duration::from_millis(45),
            inter_token_gaps: vec![Duration::from_millis(2), Duration::from_millis(3)],
            tokens_received: 2,
            bytes_received: 100,
        }
    }

    #[test]
    fn aggregates_success_and_percentiles() {
        let now = Instant::now();
        let mut agg = Aggregator::new(now - Duration::from_secs(1));
        agg.record(base_result(now, now));
        let summary = agg.finish();
        assert_eq!(summary.success, 1);
        assert_eq!(summary.streams_counted, 1);
        assert_eq!(summary.error_rate, 0.0);
        assert!(summary.ttft_from_scheduled_us.is_some());
        // hdrhistogram is a lossy-but-bounded-error structure (3 significant
        // figures here), so assert "close to 10ms", not bit-exact.
        assert_close(summary.ttft_from_scheduled_us.unwrap().p50, 10_000);
        assert_eq!(summary.tokens_received, 2);
    }

    #[test]
    fn warmup_streams_are_excluded_from_stats_but_counted() {
        let now = Instant::now();
        let warmup_end = now + Duration::from_secs(5);
        let mut agg = Aggregator::new(warmup_end);
        agg.record(base_result(now, now));
        let summary = agg.finish();
        assert_eq!(summary.streams_started, 1);
        assert_eq!(summary.warmup_excluded, 1);
        assert_eq!(summary.streams_counted, 0);
        assert!(summary.ttft_from_scheduled_us.is_none());
    }

    #[test]
    fn error_rate_reflects_all_non_success_outcomes() {
        let now = Instant::now();
        let mut agg = Aggregator::new(now - Duration::from_secs(1));
        let mut ok = base_result(now, now);
        ok.outcome = Outcome::Success;
        agg.record(ok);
        let mut http_err = base_result(now, now);
        http_err.outcome = Outcome::HttpError(500);
        agg.record(http_err);
        let mut timeout = base_result(now, now);
        timeout.outcome = Outcome::Timeout;
        agg.record(timeout);
        let summary = agg.finish();
        assert_eq!(summary.streams_counted, 3);
        assert_eq!(summary.success, 1);
        assert_eq!(*summary.http_errors.get(&500).unwrap(), 1);
        assert_eq!(summary.timeouts, 1);
        assert!((summary.error_rate - (2.0 / 3.0)).abs() < 1e-9);
    }

    #[test]
    fn coordinated_omission_a_stalled_schedule_inflates_from_scheduled_not_from_send() {
        // The whole point of `latency_from_scheduled`: a request whose
        // *slot* was 200ms ago but only just got sent (driver backlog)
        // must show that 200ms in `total_from_scheduled`, while
        // `total_from_send` (pure service time) stays small.
        let scheduled_start = Instant::now();
        let send_start = scheduled_start + Duration::from_millis(200);
        let mut result = base_result(scheduled_start, send_start);
        result.total_from_scheduled = Duration::from_millis(220);
        result.total_from_send = Duration::from_millis(20);

        let mut agg = Aggregator::new(scheduled_start - Duration::from_secs(1));
        agg.record(result);
        let summary = agg.finish();
        let from_scheduled = summary.total_from_scheduled_us.unwrap();
        let from_send = summary.total_from_send_us.unwrap();
        assert_close(from_scheduled.p50, 220_000);
        assert_close(from_send.p50, 20_000);
        assert!(from_scheduled.p50 > from_send.p50 * 5);
    }
}
