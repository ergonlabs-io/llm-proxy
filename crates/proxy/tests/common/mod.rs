//! Helpers shared by the integration tests in this directory. Each test file
//! is its own crate and pulls this in with `mod common;`; Cargo does not build
//! `tests/common/mod.rs` as a test binary of its own.

#[path = "../../../proxy-core/src/test_ports.rs"]
mod test_ports;
pub use test_ports::free_port;
