//! HTTP data plane (Lane C).
//!
//! Work packages (see internal-docs/IMPLEMENTATION_PLAN.md):
//! - WP-10: h1/h2 codec integration (downstream + upstream), including WebSocket
//!   upgrades: 101 tunnel mode and h2 extended CONNECT translation (Appendix S10).
//!   Chunk A ([`hyper_spike` test](../tests/hyper_spike.rs)) de-risked the
//!   hyper 1.x low-level `conn` API; chunk B ([`codec`], [`handler`]) is the
//!   standalone downstream HTTP/1.1 codec and the provisional `StreamHandler`
//!   seam it hands requests to. h2 downstream, HTTP upgrades (S10), the
//!   upstream codec, and wiring the codec into `proxy-core`'s listener are
//!   later chunks.
//! - WP-11: HTTP filter manager — implements the S2 iteration state machine
//!   exactly, driving the API in [`filter`]; will implement/refine the
//!   `StreamHandler` seam from chunk B; upgraded streams keep flowing
//!   through the filter chain as data (S10.2).
//! - WP-12: route table + matching engine (Appendix S1).
//! - WP-13: router filter + upstream request lifecycle (Appendices S4, S9).
//!   [`headers`] implements the S9 header-sanitization functions this WP
//!   will call.
//! - WP-14: retry & hedging engine (Appendix S3).
//!
//! The [`filter`] module is the frozen shared surface consumed by WP-31/32
//! filters and Lane H (ground rule #4).

pub mod access_logging;
pub mod codec;
pub mod filter;
pub mod filter_manager;
pub mod handler;
pub mod headers;
pub mod retry;
pub mod route;
pub mod router;
pub mod stat_handles;
pub mod stream_info;
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
    resolve_trusted_address, sanitize_hop_by_hop, set_forwarded_proto,
    strip_envoy_headers_from_external, XffOptions,
};
pub use retry::{backoff_delay, should_retry, AttemptOutcome, RetryState};
pub use route::{
    apply_prefix_rewrite, match_route, select_cluster, strip_port, strip_query, RouteMatch,
    RouteRequest,
};
pub use stream_info::{AuthInfo, LlmStats, LlmTokenUsage, StreamInfo};
