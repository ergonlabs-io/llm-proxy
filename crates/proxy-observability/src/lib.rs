//! Stats registry with Envoy-exact naming (WP-23) and the access-log formatter
//! (WP-24). This crate also owns [`ResponseFlag`] — the contract populated by the
//! router (WP-13), retry engine (WP-14) and pools (WP-15).

pub mod flags;

pub use flags::ResponseFlag;
