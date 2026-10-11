//! Scriptable in-process xDS control-plane harness:
//! a puppet SotW ADS server for integration tests. It does not
//! implement any control-plane logic (no diffing, no warming, no reconnect
//! bookkeeping) — a [`script::Script`] tells it exactly what
//! `DiscoveryResponse`s to send and when, and it records every
//! `DiscoveryRequest` it receives so tests can assert on the client's
//! request/ACK/NACK behavior.
//!
//! This crate is the core scriptable server plus its own self-tests; the
//! go-control-plane reference fixture lives in `testing/xds-conformance`.

pub mod delta;
pub mod log;
pub mod script;
pub mod server;

pub use delta::{DeltaHarness, RecordedDeltaRequest};
pub use log::{RecordedRequest, RequestKind, RequestLog};
pub use script::Step;
pub use server::{Harness, ScriptedAds};
