//! Stats registry with Envoy-exact naming (WP-23) and the access-log formatter
//! (WP-24). This crate also owns [`ResponseFlag`] — the contract populated by the
//! router (WP-13), retry engine (WP-14) and pools (WP-15).

pub mod access_log;
pub mod flags;
pub mod sink;
/// WP-23 increment 1: the stats registry core (instruments, `Handle`
/// resolution, sharded counters). Rendering to Envoy `/stats` text and
/// Prometheus lands in later increments; see
/// `docs/wp-23-stats-design-brief.md`.
pub mod stats;

pub use flags::ResponseFlag;
