//! Per-cluster latency signal for latency-aware weighted selection
//! (`envoy-divergences.md` row 48).
//!
//! One exponentially weighted moving average per cluster, per replica, held in
//! one atomic: a response folds its sample in with a compare-and-swap loop, and
//! a draw reads it with one load. No lock, no allocation, no shared store.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Weight of a new sample. A member at the selection floor still receives
/// a trickle of traffic, and at this weight a handful of its samples move
/// the average most of the way to a changed latency, so a recovered member
/// regains its share within a few dozen requests.
const ALPHA: f64 = 0.3;

/// The moving average of one cluster's response latency, in microseconds.
#[derive(Debug, Default)]
pub struct LatencyEwma {
    /// `f64::to_bits` of the average; 0 means "no sample yet".
    bits: AtomicU64,
}

impl LatencyEwma {
    /// Folds one sample in. The first sample becomes the average.
    pub fn record(&self, sample: Duration) {
        // A zero sample would read back as "no sample"; one microsecond is
        // below any real upstream latency.
        let sample = (sample.as_secs_f64() * 1e6).max(1.0);
        // Rust note: `try_update` retries the closure until its
        // compare-and-swap wins, so concurrent recorders never lose a sample.
        let _ = self
            .bits
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |bits| {
                let next = if bits == 0 {
                    sample
                } else {
                    let average = f64::from_bits(bits);
                    average + ALPHA * (sample - average)
                };
                Some(next.to_bits())
            });
    }

    /// The current average in microseconds, or `None` before any sample.
    pub fn micros(&self) -> Option<f64> {
        match self.bits.load(Ordering::Relaxed) {
            0 => None,
            bits => Some(f64::from_bits(bits)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The first sample is the average; later ones move it by `ALPHA` of the
    /// gap, so one outlier does not swing a member's share.
    #[test]
    fn the_first_sample_seeds_and_later_ones_move_it_by_alpha() {
        let ewma = LatencyEwma::default();
        assert_eq!(ewma.micros(), None);
        ewma.record(Duration::from_millis(10));
        assert_eq!(ewma.micros(), Some(10_000.0));
        ewma.record(Duration::from_millis(110));
        assert_eq!(ewma.micros(), Some(10_000.0 + ALPHA * 100_000.0));
        ewma.record(Duration::ZERO);
        assert!(ewma.micros().is_some(), "a zero sample is not 'no sample'");
    }
}
