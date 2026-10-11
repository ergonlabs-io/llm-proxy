//! xDS client.
//!
//! - ADS gRPC client (SotW), per-type subscription state machines, ACK/NACK
//!   and version/nonce bookkeeping (`internal-docs/envoy-semantics.md` S8).
//! - Warming, update ordering, make-before-break listener/cluster swaps.
//! - SDS, delta xDS, and the filesystem xDS transport
//!   (`internal-docs/architecture.md` §12.3 rule 1: the subscription layer is
//!   transport-agnostic, gRPC or file-watch behind one trait).
//!
//! Scale rule (`internal-docs/architecture.md` §12.2 rule 5): on any xDS
//! failure keep serving last-good config with backoff -- never NACK-storm,
//! never shed state.

pub mod apply;
pub mod authorization;
pub mod backoff;
pub mod client;
pub mod delta_client;
pub mod delta_subscription;
pub mod filesystem;
pub mod secret;
pub mod store;
pub mod subscription;

pub use apply::{
    InitializationEvent, InitializationSink, Publish, PublishEndpoints, PublishSecrets,
    ResourceApplier, SecretUpdate,
};
pub use backoff::BackoffPolicy;
pub use client::{AdsClient, AdsError, FnHandler, Reconnect, ResponseHandler, Sleep, Validator};
pub use delta_client::{
    DeltaAdsClient, DeltaAdsError, DeltaResponseHandler, DeltaValidator, FnDeltaHandler,
};
pub use delta_subscription::{DeltaRequest, DeltaSubscriptionState, ResourceVersion};
pub use filesystem::{FileSource, FileSourceError, FileWatcher};
pub use proxy_config::ir::{DynamicSecret, SecretKind};
pub use store::{ApplyError, ApplyOutcome, DeltaApplyError, SetSemantics, SotwSet};
pub use subscription::{Request, Subscription, SubscriptionState, Verdict};
