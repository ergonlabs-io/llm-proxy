//! xDS client (Lane E).
//!
//! Work packages (see IMPLEMENTATION_PLAN.md):
//! - WP-20: ADS gRPC client (SotW), per-type subscription state machines,
//!   ACK/NACK + version/nonce bookkeeping (Appendix S8).
//! - WP-21: warming, update ordering, make-before-break listener/cluster swaps.
//! - WP-22: SDS, delta xDS, and the filesystem xDS transport (PLAN.md Part 9.1 —
//!   the subscription layer is transport-agnostic: gRPC | file-watch behind one trait).
//!
//! Scale rule (PLAN.md Part 8.5): on any xDS failure keep serving last-good
//! config with backoff — never NACK-storm, never shed state.

pub mod backoff;
pub mod client;
pub mod subscription;

pub use backoff::BackoffPolicy;
pub use client::{AdsClient, AdsError, Reconnect, Sleep, Validator};
pub use subscription::{Request, Subscription, SubscriptionState, Verdict};
