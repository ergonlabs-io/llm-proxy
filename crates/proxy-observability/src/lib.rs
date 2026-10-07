//! Stats registry with Envoy-exact naming (WP-23) and the access-log formatter
//! (WP-24). This crate also owns [`ResponseFlag`] — the contract populated by the
//! router (WP-13), retry engine (WP-14) and pools (WP-15).

pub mod access_log;
#[cfg(unix)]
pub mod capture;
pub mod capture_policy;
#[cfg(all(test, unix))]
mod capture_tests;
#[cfg(unix)]
pub mod capture_transport;
pub mod flags;
pub mod metadata;
/// WP-51 increment 3a: maps [`trace::FinishedSpan`] to the OTLP wire types
/// and drains a [`trace::SpanSink`]'s receiver into a real collector.
pub mod otlp;
/// End-user request-record contracts. This module intentionally contains no
/// storage client or request-body capture implementation.
pub mod records;
pub mod sink;
/// WP-23 increments 1–3: the stats registry core (instruments, `Handle`
/// resolution, sharded counters/histograms) and the Envoy `/stats` text
/// renderer (`stats::envoy_render`). Prometheus rendering (`/stats/prometheus`)
/// lands in a later increment; see `internal-docs/IMPLEMENTATION_PLAN.md`.
pub mod stats;
/// WP-51 increment 2 foundation: our own span model plus W3C `traceparent`
/// parsing. Pure library, not wired into the request path yet.
pub mod trace;

pub use flags::ResponseFlag;
