//! HTTP data plane (Lane C).
//!
//! Work packages (see IMPLEMENTATION_PLAN.md):
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
//! - WP-14: retry & hedging engine (Appendix S3).
//!
//! The [`filter`] module is the frozen shared surface consumed by WP-31/32
//! filters and Lane H (ground rule #4).

pub mod codec;
pub mod filter;
pub mod handler;
pub mod stream_info;

pub use codec::{serve_http1, CodecError, Http1Options};
pub use filter::{
    FilterDataStatus, FilterHeadersStatus, FilterRegistry, FilterTrailersStatus, HttpFilter,
    HttpFilterFactory,
};
pub use handler::{BodyError, HttpRequestParts, HttpResponseParts, StreamBody, StreamHandler};
pub use stream_info::StreamInfo;
