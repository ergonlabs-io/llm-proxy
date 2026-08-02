//! Admin server (WP-25 / WP-50 increment 1: the read-only surface).
//!
//! Endpoints, this increment: `/ready`, `/config_dump`, `/clusters`,
//! `/server_info`. Everything else 404s, naming the endpoints that exist.
//! `/stats` is a deliberate 404 (WP-23's stats registry doesn't exist yet)
//! rather than a fake empty `200` -- an operator who trusts an empty
//! `/stats` believes there is no traffic. `/quitquitquit`,
//! `/drain_listeners`, and `/logging` are mutating and out of scope for a
//! read-only increment.
//!
//! Runs on the control runtime with its own tiny `hyper` server -- **never**
//! the data plane (ADR-0003 makes the data plane `!Send`/worker-local; this
//! is an ordinary `Send` tokio task, same lane as stats aggregation and
//! drain coordination). It reads the live [`proxy_config::ConfigSnapshot`]
//! through a [`proxy_core::WorkerConfigHandle`] (control side: read, don't
//! own) rather than cloning it per request.
//!
//! ## Redaction policy
//!
//! `/config_dump` is **default-deny (allowlist), not blocklist.** Every type
//! in [`dump`] is a hand-picked, hand-serialized view of the IR -- there is
//! no `#[derive(Serialize)]` anywhere on an IR type, on purpose. A blocklist
//! ("hide the fields we know are secret") leaks silently the day someone
//! adds a new field to `ir.rs` and nothing here even notices; an allowlist
//! ("show only the fields we decided are safe") instead leaves that new
//! field invisible until a person deliberately adds it to a `*Dump` struct.
//! For a debugging endpoint that a future contributor will extend without
//! re-reading this file, invisible-by-default is the only safe failure mode.
//!
//! Concretely, this means:
//! - `RouteEntry.request_headers_to_add` values -- exactly how provider API
//!   keys are injected upstream (WP-34/WP-50 history) -- always render as
//!   `"[redacted]"`. Only the header **name** is shown, which is what an
//!   operator debugging auth actually needs.
//! - TLS private keys, certificate chains, and any `DataSourceIR::File`
//!   path's *contents* are never rendered. `dump::ClusterDump`/
//!   `dump::FilterChainDump` only expose `tls: bool` (is TLS configured at
//!   all), never the `TlsCertificateIR`/`ValidationContextIR` underneath.
//! - `HttpFilterSpec.config` / `PerFilterConfig.config` (both opaque
//!   `prost_reflect::DynamicMessage`s this crate has never vetted per
//!   filter) are never rendered -- only the filter's name/type URL.
//! - `TlsSecret`s appear by **name only**.
//!
//! See `dump.rs` for the field-by-field allowlist this enforces.

pub mod dump;
pub mod server;

pub use server::{serve, AdminError, AdminServer};
