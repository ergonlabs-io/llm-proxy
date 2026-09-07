//! Admin server (WP-25 / WP-50 increment 1: the read-only surface; WP-50
//! increment 3b-ii W4 adds a bearer-gated write API for the control plane).
//!
//! Read endpoints, ungated: `/ready`, `/config_dump`, `/clusters`,
//! `/server_info`, `/stats`, `/stats/prometheus`. `/stats`(`/prometheus`) is
//! a deliberate 404 when no WP-23 stats registry is wired rather than a fake
//! empty `200` -- an operator who trusts an empty `/stats` believes there is
//! no traffic. `/ready` (WP-21 increment 3) is `200 "LIVE"` unless a
//! [`server::ReadinessProbe`] was wired AND reports still-warming clusters,
//! in which case it is `503 "INITIALIZING"` -- see that type's doc for the
//! injected-closure seam and `crates/proxy/src/main.rs` for the production
//! probe and its warming deadline.
//!
//! **The one exception: `GET /tenants/{id}/spend` (WP-50 increment 3c-iv) is
//! a READ that is nonetheless gated exactly like a write.** Every other read
//! above is deliberately non-sensitive -- config shape, cluster names,
//! aggregate stats -- but per-tenant spend is financial data: how much a
//! specific tenant has billed, against what ceiling, this period. Nothing
//! about it should be answerable to an unauthenticated caller just because
//! the HTTP verb is `GET`. See `server.rs`'s `handle` and `WriteRoute`'s doc
//! for how a GET route shares the write API's gate/resolution machinery.
//!
//! Write endpoints, gated by the `LLMPROXY_ADMIN_TOKEN` bearer token (see
//! `server::serve`'s doc for why that env var is read in `crates/proxy`, not
//! here): `POST /keys` (mint), `DELETE /keys/{id}` (revoke),
//! `POST /tenants` (create), `DELETE /tenants/{id}` (delete),
//! `PUT /tenants/{id}/policy` (set model-access policy),
//! `PUT /tenants/{id}/budget` (set or clear a tenant's spend ceiling -- WP-50
//! increment 3c-iii-a; storage and admin CRUD only, the enforcing filter is a
//! later increment), and the read described above,
//! `GET /tenants/{id}/spend` (WP-50 increment 3c-iv). Unset (or
//! empty/whitespace) token means every one of these -- write OR read -- is
//! refused with 403 -- **unset never means open** (CLAUDE.md rule 17). See
//! `server.rs`'s `handle` for the full gate and its per-endpoint doc
//! comments for request/response shapes.
//!
//! `PUT .../budget`'s body is `{"budget": {"max_usd": "500.00", "period":
//! "monthly"}}` to set a ceiling, or `{"budget": null}` to clear it (revert
//! to unlimited) -- one optional field expresses both set and clear
//! unambiguously, with no separate sentinel to invent. `max_usd` is parsed
//! by `proxy_filters::spend::parse_micro_usd`, the SAME parser a configured
//! price uses, so a budget can never be expressed more precisely than a
//! price. See `proxy_filters::spend::TenantBudget`'s doc for why an absent
//! budget (unlimited) and an explicitly configured zero ceiling are kept
//! distinct rather than collapsed.
//!
//! WP-50 3c-ii-a added a **scoped** form of every write endpoint (and, since
//! 3c-iv, the gated spend read too),
//! `/chains/{stat_prefix}/keys`, `/chains/{stat_prefix}/keys/{id}`,
//! `/chains/{stat_prefix}/tenants`, `/chains/{stat_prefix}/tenants/{id}`,
//! `/chains/{stat_prefix}/tenants/{id}/policy`,
//! `/chains/{stat_prefix}/tenants/{id}/budget`,
//! `/chains/{stat_prefix}/tenants/{id}/spend` -- addressed by the target
//! HTTP connection manager's own operator-chosen `stat_prefix`, ALWAYS
//! correct regardless of how many chains in this serve configure
//! `llmproxy.auth`. The original unscoped endpoints (`/keys`, ...) stay: a
//! convenience alias that succeeds only when exactly one chain in this serve
//! configures `llmproxy.auth`, and explicitly refuses (rather than guessing)
//! when more than one does -- see `server::resolve_control_plane`'s doc for
//! why guessing would be a real cross-tenant write hazard, and
//! `internal-docs/wp-50-3c-spend-budgets.md`'s "addressing follows Envoy"
//! for why `stat_prefix`, not the internal positional chain identity, is the
//! externally-addressable name.
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

pub use server::{serve, AdminError, AdminServer, Readiness, ReadinessProbe};
