//! Scriptable in-process xDS control-plane harness (WP-28, first chunk):
//! a puppet SotW ADS server for Lane E integration tests. It does not
//! implement any control-plane logic (no diffing, no warming, no reconnect
//! bookkeeping) — a [`script::Script`] tells it exactly what
//! `DiscoveryResponse`s to send and when, and it records every
//! `DiscoveryRequest` it receives so tests can assert on the client's
//! request/ACK/NACK behavior (WP-20..22).
//!
//! Later WP-28 chunks add the scenario DSL for NACK-recovery/warming races
//! and a go-control-plane docker fixture; this chunk is only the core
//! scriptable server plus its own self-tests.

pub mod log;
pub mod script;
pub mod server;

pub use log::{RecordedRequest, RequestKind, RequestLog};
pub use script::Step;
pub use server::{Harness, ScriptedAds};
