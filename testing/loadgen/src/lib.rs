//! Load-generator core (Phase 1): answers "how many concurrent, mostly-idle
//! LLM streams can one `llm-proxy` sustain, and how much latency does it
//! add?" -- see the crate's task brief for the full measurement model.
//!
//! Phase 2 (this crate now includes it): sampling the proxy process's own
//! resource usage ([`sampler`]), the ramp-hold-bisect search for the
//! capacity ceiling ([`sweep`]), and the resulting capacity report
//! ([`report::CapacityReport`]).
//!
//! Independent of `testing/diffrig`'s mock upstream types by design: this
//! crate only assumes the wire shapes (SSE framing per dialect) that both
//! real providers and diffrig's mocks emit, never diffrig's Rust types.

pub mod dialect;
pub mod driver;
pub mod metrics;
pub mod report;
pub mod rig;
pub mod sampler;
pub mod sse;
pub mod sweep;
