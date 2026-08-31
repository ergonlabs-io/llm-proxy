//! Admin server (WP-25 / WP-50 increment 1: the read-only surface; WP-50
//! increment 3b-ii W4 adds a bearer-gated write API for the control plane).
//!
//! Read endpoints, ungated: `/ready`, `/config_dump`, `/clusters`,
//! `/server_info`, `/stats`, `/stats/prometheus`. `/stats`(`/prometheus`) is
//! a deliberate 404 when no WP-23 stats registry is wired rather than a fake
//! empty `200` -- an operator who trusts an empty `/stats` believes there is
//! no traffic.
//!
//! Write endpoints, gated by the `LLMPROXY_ADMIN_TOKEN` bearer token (see
//! `server::serve`'s doc for why that env var is read in `crates/proxy`, not
//! here): `POST /keys` (mint), `DELETE /keys/{id}` (revoke),
//! `POST /tenants` (create), `DELETE /tenants/{id}` (delete),
//! `PUT /tenants/{id}/policy` (set model-access policy). Unset (or
//! empty/whitespace) token means every write is refused with 403 --
//! **unset never means open** (CLAUDE.md rule 17). See `server.rs`'s
//! `handle` for the full gate and its per-endpoint doc comments for request/
//! response shapes.
//!
//! Everything else 404s, naming the endpoints that exist. `/quitquitquit`,
//! `/drain_listeners`, and `/logging` (Envoy's own admin mutating
//! endpoints) are not part of this API and stay 404.
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
//!
//! **The one deliberate exception, and it is deliberate:** `POST /keys`
//! returns a freshly minted virtual key's PLAINTEXT in its response body.
//! That is the entire point of the endpoint -- the store keeps only the
//! HMAC digest, so this response is the last moment the value exists (see
//! `proxy_filters::control::MintedKey`). It is not a leak of something the
//! allowlist above should have caught: nothing reads it back out, no other
//! endpoint can return it, and `server/tests.rs` asserts that a minted
//! plaintext never appears in `/config_dump` or `/clusters`. If you add an
//! endpoint that can surface an existing key's plaintext, you have broken
//! the design, not extended it.

pub mod dump;
pub mod server;

pub use server::{serve, AdminError, AdminServer};
