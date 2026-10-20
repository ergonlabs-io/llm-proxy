//! Stats registry with Envoy-exact naming and the access-log formatter. This
//! crate also owns [`ResponseFlag`] — the contract populated by the router,
//! retry engine and pools.

pub mod access_log;
#[cfg(unix)]
pub mod capture;
pub mod capture_policy;
#[cfg(all(test, unix))]
mod capture_tests;
#[cfg(unix)]
pub mod capture_transport;
pub mod chargeback;
pub mod flags;
pub mod ledger;
#[cfg(all(test, unix))]
mod ledger_tests;
pub mod metadata;
/// Maps [`trace::FinishedSpan`] to the OTLP wire types
/// and drains a [`trace::SpanSink`]'s receiver into a real collector.
pub mod otlp;
/// End-user request-record contracts. This module intentionally contains no
/// storage client or request-body capture implementation.
pub mod records;
pub mod sink;
/// The stats registry core (instruments, `Handle`
/// resolution, sharded counters/histograms) and the Envoy `/stats` text
/// renderer (`stats::envoy_render`). Prometheus rendering (`/stats/prometheus`)
/// lives in `stats::prometheus_render`.
pub mod stats;
/// Our own span model plus W3C `traceparent`
/// parsing. Pure library, not wired into the request path yet.
pub mod trace;
/// Trace export (ADR-0008): request and response bodies of opted-in
/// tenants, off the worker, into compressed segments.
pub mod traces;

pub use flags::ResponseFlag;
