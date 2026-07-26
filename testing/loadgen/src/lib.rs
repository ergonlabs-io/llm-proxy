//! Load-generator core (Phase 1): answers "how many concurrent, mostly-idle
//! LLM streams can one `llm-proxy` sustain, and how much latency does it
//! add?" -- see the crate's task brief for the full measurement model.
//!
//! Deliberately NOT here (Phase 2, a separate task): sampling the proxy
//! process's own resource usage, the N-sweep search for the capacity
//! ceiling, and rendering a report. This crate's job is to drive load
//! correctly and honestly and emit self-describing JSON
//! ([`report::RunReport`]) that a later phase can consume.
//!
//! Independent of `testing/diffrig`'s mock upstream types by design: this
//! crate only assumes the wire shapes (SSE framing per dialect) that both
//! real providers and diffrig's mocks emit, never diffrig's Rust types.

pub mod dialect;
pub mod driver;
pub mod metrics;
pub mod report;
pub mod rig;
pub mod sse;
