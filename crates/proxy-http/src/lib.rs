//! HTTP data plane (Lane C).
//!
//! Work packages (see IMPLEMENTATION_PLAN.md):
//! - WP-10: h1/h2 codec integration (downstream + upstream), including WebSocket
//!   upgrades: 101 tunnel mode and h2 extended CONNECT translation (Appendix S10).
//! - WP-11: HTTP filter manager — implements the S2 iteration state machine
//!   exactly, driving the API in [`filter`]; upgraded streams keep flowing
//!   through the filter chain as data (S10.2).
//! - WP-12: route table + matching engine (Appendix S1).
//! - WP-13: router filter + upstream request lifecycle (Appendices S4, S9).
//! - WP-14: retry & hedging engine (Appendix S3).
//!
//! The [`filter`] module is the frozen shared surface consumed by WP-31/32
//! filters and Lane H (ground rule #4).

pub mod filter;
pub mod stream_info;

pub use filter::{
    FilterDataStatus, FilterHeadersStatus, FilterRegistry, FilterTrailersStatus, HttpFilter,
    HttpFilterFactory,
};
pub use stream_info::StreamInfo;
