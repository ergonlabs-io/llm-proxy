//! Admin server: a read-only surface plus a bearer-gated write API for the control plane.
//!
//! Ungated reads: `/ready`, `/config_dump`, `/clusters`, `/server_info`, `/stats`, `/stats/prometheus`, and
//! `/models` (the model inventory; see `dump::models_from_snapshot`). `/stats` returns a deliberate 404 when no
//! registry is wired, rather than an empty `200`, since an empty `/stats` reads as no traffic. `/ready` is
//! `200 "LIVE"`, or `503 "INITIALIZING"` when a [`server::ReadinessProbe`] reports warming clusters, or
//! `503 "DRAINING"` after a failed health check or a started drain.
//!
//! Two reads are gated like writes: `GET /tenants/{id}/spend` and the key listing `GET /keys` (and its scoped
//! form). Spend is financial data, and a key listing is identity data. Neither should be answerable to an
//! unauthenticated caller just because the verb is `GET`. See `server.rs`'s `handle` and `WriteRoute`.
//!
//! Gated writes take the `LLMPROXY_ADMIN_TOKEN` bearer token (read by `crates/proxy`, see `server::serve`):
//! `POST /keys` (mint), `DELETE /keys/{id}`, `POST /tenants`, `DELETE /tenants/{id}`, `PUT /tenants/{id}/policy`,
//! `PUT /keys/{id}/policy`, `PUT /tenants/{id}/budget`, `PUT /keys/{id}/budget`, `PUT /tenants/{id}/limits`,
//! `PUT /keys/{id}/limits`, and `PUT /tenants/{id}/provider_credentials/{provider}`. An unset, empty, or
//! whitespace-only token refuses every gated route with 403. **Unset never means open** (AGENTS.md "Fail-open
//! controls").
//!
//! Budget bodies are `{"budget": {"max_usd": "500.00", "period": "monthly"}}` to set, or `{"budget": null}` to
//! clear. `max_usd` goes through `proxy_control::spend::parse_micro_usd`, the same parser a configured price
//! uses. Limit bodies are `{"limits": null}` or an object with optional `tokens_per_minute`,
//! `requests_per_minute`, and `concurrent_streams`. An omitted field sets no limit, and zero is an explicit
//! refusal. With a shared store, counters and concurrent-stream leases are shared across replicas (ADR-0006).
//! Otherwise N replicas can admit up to N times a configured limit.
//!
//! Every write and gated read also has a scoped form under `/chains/{stat_prefix}/...`, addressed by the HTTP
//! connection manager's operator-chosen `stat_prefix`. The scoped form is always correct, however many chains
//! configure `llmproxy.auth`. The unscoped endpoints remain as a convenience that succeeds only when exactly one
//! chain configures `llmproxy.auth`. They refuse rather than guess when more than one does (see
//! `server::resolve_control_plane`). Envoy addresses an HTTP connection manager by its `stat_prefix` in the same
//! way.
//!
//! Lifecycle POSTs behind the same gate: `/healthcheck/fail` (`/ready` answers DRAINING), `/healthcheck/ok` (never
//! undoes a drain), and `/drain_listeners` (starts the same drain as SIGTERM; `?graceful` and `?inboundonly` are
//! accepted with no extra effect, other query parameters are a 400). Without a wired lifecycle they answer 404. See
//! `internal-docs/envoy-divergences.md`.
//!
//! Capture-agent inspection: `GET /capture/spool/stats` (ungated counters) and `GET /capture/spool/records` (gated
//! like spend, since records are end-user metadata). Each query opens a fresh handshaken connection under a 2 s
//! deadline. Both answer 404 with no agent configured, 503 when it is unreachable, 403 when the producer grant lacks
//! `"inspect": true`, and 501 when the agent predates inspection. The stats answer is cached for 5 s, single-flight,
//! errors included. Records are never cached.
//!
//! Billing ledger (ADR-0009 decision 8), both gated like spend: `GET /ledger/entries?after=&limit=` returns
//! committed entries by cursor, and `POST /ledger/ack?through=` removes them from the spool, which also clears a
//! disk-cap hold. Both are answered by the ledger's writer thread and waited on from a blocking pool thread, never a
//! request worker. Without a ledger both answer 404.
//!
//! Everything else 404s, naming the endpoints that exist. `/quitquitquit`, `/logging`, and `/listeners` (Envoy admin
//! endpoints) are not part of this API.
//!
//! The admin UI (`admin-ui/`, built by `make ui-build`) is served from memory under `/ui` when
//! `LLMPROXY_ADMIN_UI_DIR` points at the build output (see [`server::UiAssets`]). It is same-origin, so it needs no
//! CORS. Without the env var `/ui` 404s with a hint.
//!
//! The server runs on the control runtime as an ordinary `Send` tokio task, never on the data plane (ADR-0003). It
//! reads the live [`proxy_config::ConfigSnapshot`] through a [`proxy_core::WorkerConfigHandle`].
//!
//! ## Redaction policy
//!
//! `/config_dump` is default-deny. Every type in [`dump`] is a hand-picked view of the IR, with no
//! `#[derive(Serialize)]` on any IR type. A blocklist leaks silently when a new IR field appears. An allowlist keeps
//! a new field invisible until someone adds it to a `*Dump` struct on purpose.
//!
//! Concretely:
//! - `RouteEntry.request_headers_to_add` values, which is how provider API keys are injected, always render as
//!   `"[redacted]"`. Only the header name is shown.
//! - TLS private keys, certificate chains, and the contents of any `DataSourceIR::File` are never rendered.
//!   Clusters and filter chains expose only `tls: bool`.
//! - `HttpFilterSpec.config` and `PerFilterConfig.config` (opaque messages this crate does not vet per filter) are
//!   never rendered. Only the name and type URL are.
//! - `TlsSecret`s appear by name only.
//!
//! See `dump.rs` for the field-by-field allowlist.
//!
//! The one deliberate exception: `POST /keys` returns a freshly minted key's plaintext in its response body. The
//! store keeps only the HMAC digest, so this response is the last moment the value exists (see
//! `proxy_control::control::MintedKey`). Nothing reads it back, no other endpoint returns it, and `server/tests.rs`
//! asserts that a minted plaintext never appears in `/config_dump` or `/clusters`. An endpoint that can surface an
//! existing key's plaintext would break the design.

pub mod dump;
pub mod server;

pub use dump::{LiveCluster, LiveEndpoint};
pub use server::{
    serve, AdminError, AdminRuntime, AdminServer, CaptureAgentProvider, ClusterStateProvider,
    Readiness, ReadinessProbe, UiAssets,
};
