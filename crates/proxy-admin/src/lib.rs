//! Admin server: a read-only surface plus a bearer-gated write API for the
//! control plane.
//!
//! Read endpoints, ungated: `/ready`, `/config_dump`, `/clusters`,
//! `/server_info`, `/stats`, `/stats/prometheus`, and `/models` (every route
//! the loaded config matches on the `x-llmproxy-model` header -- the model
//! inventory; see `dump::models_from_snapshot` for what counts). `/stats`
//! (`/prometheus`) is
//! a deliberate 404 when no stats registry is wired rather than a fake
//! empty `200` -- an operator who trusts an empty `/stats` believes there is
//! no traffic. `/ready` is `200 "LIVE"` unless a
//! [`server::ReadinessProbe`] was wired AND reports still-warming clusters,
//! in which case it is `503 "INITIALIZING"` -- see that type's doc for the
//! injected-closure seam and `crates/proxy/src/main.rs` for the production
//! probe and its warming deadline. A third state, `503 "DRAINING"`, covers
//! both a failed health check and a started drain (one shared
//! [`proxy_core::lifecycle::LifecycleState`], read by that same probe).
//!
//! **Two READS are nonetheless gated exactly like writes: `GET
//! /tenants/{id}/spend` and the key listing `GET
//! /keys` / `GET /chains/{stat_prefix}/keys`.** Every other read above is
//! deliberately non-sensitive -- config shape, cluster names, model
//! patterns, aggregate stats -- but per-tenant spend is financial data (how
//! much a specific tenant has billed, against what ceiling, this period) and
//! a key listing is identity data (which key ids exist, who owns each,
//! whether it was revoked, what it may spend). Nothing about either should
//! be answerable to an unauthenticated caller just because the HTTP verb is
//! `GET`. See `server.rs`'s `handle` and `WriteRoute`'s doc for how a GET
//! route shares the write API's gate/resolution machinery.
//!
//! Write endpoints, gated by the `LLMPROXY_ADMIN_TOKEN` bearer token (see
//! `server::serve`'s doc for why that env var is read in `crates/proxy`, not
//! here): `POST /keys` (mint), `DELETE /keys/{id}` (revoke),
//! `POST /tenants` (create), `DELETE /tenants/{id}` (delete),
//! `PUT /tenants/{id}/policy` (set model-access policy),
//! `PUT /keys/{id}/policy` (narrow a key's model access),
//! `PUT /tenants/{id}/budget` (set or clear a tenant's spend ceiling), and
//! `PUT /tenants/{id}/limits` and `PUT /keys/{id}/limits` (set or clear rate
//! ceilings), plus `PUT /keys/{id}/budget`, and
//! the reads described above, `GET /tenants/{id}/spend` and `GET /keys` (the
//! key listing: `key_id`, `tenant`, `revoked`, `budget`, `limits`, `policy`, sorted by
//! `(tenant, key_id)`). Unset (or
//! empty/whitespace) token means every one of these -- write OR read -- is
//! refused with 403 -- **unset never means open** (AGENTS.md "Fail-open controls"). See
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
//! `PUT .../limits` accepts `{"limits": null}` to clear, or an object with
//! optional `tokens_per_minute`, `requests_per_minute`, and
//! `concurrent_streams` fields. Omitted fields set no limit; zero is an
//! explicit refusal at that scope. A tenant limit bounds all its keys, and a
//! key limit can narrow it. With a shared store the counters and the
//! concurrent-stream leases are shared across replicas (ADR-0006); with any
//! other store, N replicas can admit up to N times a configured limit.
//!
//! Every write endpoint also has a **scoped** form (as do the gated spend
//! read and the `GET /keys` listing),
//! `/chains/{stat_prefix}/keys` (POST to mint, GET to list), `/chains/{stat_prefix}/keys/{id}`,
//! `/chains/{stat_prefix}/keys/{id}/policy`,
//! `/chains/{stat_prefix}/keys/{id}/limits`,
//! `/chains/{stat_prefix}/tenants`, `/chains/{stat_prefix}/tenants/{id}`,
//! `/chains/{stat_prefix}/tenants/{id}/policy`,
//! `/chains/{stat_prefix}/tenants/{id}/budget`,
//! `/chains/{stat_prefix}/tenants/{id}/limits`,
//! `/chains/{stat_prefix}/tenants/{id}/spend` -- addressed by the target
//! HTTP connection manager's own operator-chosen `stat_prefix`, ALWAYS
//! correct regardless of how many chains in this serve configure
//! `llmproxy.auth`. The original unscoped endpoints (`/keys`, ...) stay: a
//! convenience alias that succeeds only when exactly one chain in this serve
//! configures `llmproxy.auth`, and explicitly refuses (rather than guessing)
//! when more than one does -- see `server::resolve_control_plane`'s doc for
//! why guessing would be a real cross-tenant write hazard, and
//! Envoy's convention of addressing an HTTP connection manager by its
//! operator-chosen `stat_prefix` for why `stat_prefix`, not the internal
//! positional chain identity, is the externally-addressable name.
//!
//! Three more POST endpoints sit behind the same token gate and drive the
//! shared lifecycle state: `/healthcheck/fail` (`/ready` answers DRAINING),
//! `/healthcheck/ok` (clears that, but never undoes a drain), and
//! `/drain_listeners` (starts the same drain as SIGTERM; the process keeps
//! running until a signal arrives; `?graceful` and `?inboundonly` are accepted
//! with no extra effect, any other query parameter is a 400). Without a wired
//! lifecycle they answer 404. See `internal-docs/envoy-divergences.md`.
//!
//! Capture-agent inspection: `GET /capture/spool/stats` (ungated spool
//! counters) and `GET /capture/spool/records?after=&limit=` (stored request
//! records; **gated like the spend read**, since they are end-user metadata).
//! Each query opens a fresh handshaken connection to the capture agent under a
//! 2 s deadline. Both answer 404 when no agent endpoint is configured, 503
//! when it is unreachable, 403 when the agent's producer grant lacks
//! `"inspect": true`, and 501 when the agent closes on the query because it
//! predates inspection (retrying cannot help; upgrade it). The ungated stats
//! answer is cached for 5 s (single-flight, errors included), so a flood
//! costs the agent at most one query per 5 s; records are never cached.
//!
//! Everything else 404s, naming the endpoints that exist. `/quitquitquit`,
//! `/logging`, and `/listeners` (Envoy admin endpoints) are not part of this
//! API and stay 404.
//!
//! The single-page admin UI (`admin-ui/`, built by `make ui-build`) is served
//! from memory under `GET /ui`, `GET /ui/`, and `GET /ui/<asset>` when the
//! binary was started with `LLMPROXY_ADMIN_UI_DIR` pointing at the build
//! output -- see [`server::UiAssets`]. Same-origin by construction, so the UI
//! needs no CORS and the bearer token stays first-party. Without the env var
//! `/ui` 404s with a hint rather than an empty 200.
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
//!   keys are injected upstream -- always render as
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

pub use dump::{LiveCluster, LiveEndpoint};
pub use server::{
    serve, AdminError, AdminRuntime, AdminServer, CaptureAgentProvider, ClusterStateProvider,
    Readiness, ReadinessProbe, UiAssets,
};
