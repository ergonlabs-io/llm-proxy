//! HTTP data plane.
//!
//! - Codec ([`codec`], [`handler`]): downstream and upstream h1/h2, including
//!   WebSocket upgrades (101 tunnel mode and h2 extended CONNECT translation,
//!   envoy-semantics.md S10). The `StreamHandler` seam is what the codec hands
//!   each request to; `tests/hyper_spike.rs` records the hyper 1.x
//!   capability findings the codec design rests on.
//! - Filter manager ([`filter_manager`]): implements the S2 iteration state
//!   machine exactly, driving the API in [`filter`]; upgraded streams keep
//!   flowing through the filter chain as data (S10.2).
//! - Route table and matching engine ([`route`], envoy-semantics.md S1).
//! - Router filter and upstream request lifecycle ([`router`],
//!   envoy-semantics.md S4, S9). [`headers`] implements the S9
//!   header-sanitization functions the router calls.
//! - Retry and hedging engine ([`retry`], envoy-semantics.md S3).
//!
//! The [`filter`] module is the frozen shared surface consumed by the other
//! HTTP filters (AGENTS.md invariant 8).

pub mod access_logging;
pub mod active_requests;
mod attempt_logging;
#[cfg(unix)]
mod capture_cleanup;
pub mod codec;
pub mod credential_probe;
mod credential_provider;
pub mod filter;
pub mod filter_manager;
pub mod handler;
pub mod headers;
pub mod retry;
pub mod route;
pub mod router;
pub mod stat_handles;
pub mod stream_info;
pub mod tenant_credentials;
pub mod upstream_pool;

pub use codec::{serve_http1, CodecError, Http1Options};
pub use filter::{
    FactoryContext, FilterDataStatus, FilterHeadersStatus, FilterRegistry, FilterTrailersStatus,
    HttpFilter, HttpFilterFactory, SharedFactoryState,
};
pub use filter_manager::{FilterChainHandler, DEFAULT_BUFFER_LIMIT};
pub use handler::{
    BodyError, DownstreamInfo, HttpRequestParts, HttpResponseParts, StreamBody, StreamHandler,
};
pub use headers::{
    apply_xff, ensure_request_id, generate_request_id, is_internal_request,
    resolve_trusted_address, sanitize_hop_by_hop, sanitize_upgrade_hop_by_hop, set_forwarded_proto,
    strip_envoy_headers_from_external, XffOptions,
};
pub use retry::{backoff_delay, should_retry, AttemptOutcome, RetryState};
pub use route::{
    apply_prefix_rewrite, match_route, select_cluster, strip_port, strip_query, RouteMatch,
    RouteRequest,
};
pub use stream_info::{AuthInfo, LlmListCost, LlmStats, LlmTokenUsage, StreamInfo};
