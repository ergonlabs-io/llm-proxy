//! Non-core filters, registered by Envoy extension type URL (or, for Lane H,
//! under `type.llmproxy.dev/...`).
//!
//! Work packages (see internal-docs/IMPLEMENTATION_PLAN.md):
//! - WP-31: cors, local_ratelimit, header mutation.
//! - WP-32: ext_authz, ratelimit (gRPC RLS), ext_proc (client side).
//! - Lane H (LLM layer):
//!   - WP-33: streaming-first guarantees + GenAI observability (TTFT/TPOT).
//!     [`usage_filter`] wires the WP-34 extractor below into the real encode
//!     path.
//!   - WP-34: token metering & token-based rate limiting (budget-store seam).
//!     [`token_limit`] is the budget limiter itself, increment 1: a pure
//!     library ([`token_limit::BudgetStore`] trait + its in-process impl).
//!     Increment 2 ([`token_limit_filter`]) wires it into a real decode/encode
//!     `HttpFilter` (check on decode, record on encode-end) under
//!     `type.llmproxy.dev/envoy.type.v3.TokenBucket`. The dialect `limits`
//!     config surface (increment 3) is not built here.
//!   - WP-35: model routing (body peek -> cluster_header) & provider fallback.
//!   - WP-36: Gateway API Inference Extension endpoint-picker support.
//!   - WP-37: realtime WebSocket sessions (session-pinned routing, frame-aware
//!     token metering, session quotas, Close-frame drains) — Appendix S10.
//!   - WP-45: bounded request-body prefix scan + splice
//!     ([`body_rewrite`]), shared by forced usage reporting and body-based
//!     model routing. Increment 1: the scanner/policy library only, not yet
//!     wired into a filter. Increment 2b ([`body_rewrite_filter`]) wires it
//!     into a real decode-path `HttpFilter`, consumer A only (forced
//!     `stream_options.include_usage` for OpenAI-dialect streaming requests).
//!     Consumer B (body-based model routing) is not built here.
//!   - WP-50: downstream authentication. [`auth`] is increment 2a-i: the pure
//!     library core (`Authenticator` trait, `Principal`, the virtual-key
//!     HMAC authenticator, and the `AuthenticatorChain` seam a future
//!     `JwtAuthenticator` slots into). Increment 2a-ii ([`auth_filter`]) wires
//!     it into a real decode-path `HttpFilter` under
//!     `type.llmproxy.dev/llmproxy.filters.v0.Authentication`. The token
//!     limiter is not yet re-keyed onto `Principal.tenant` -- see
//!     `docs/wp-50-auth-design-brief.md`. Increment 3a ([`model_authz`] +
//!     [`model_authz_filter`]) adds per-tenant model allow-lists: a pure
//!     `ModelAccess`/`ModelPattern` matcher plus a decode-path `HttpFilter`
//!     (`llmproxy.model_authz`) that must run after both `llmproxy.auth`
//!     (needs the tenant) and `llmproxy.body_rewrite` (needs the model) --
//!     see `internal-docs/wp-50-inc3-design-brief.md`. Increment 3b-i
//!     ([`control`]) adds the `ControlPlaneStore` trait, an in-memory impl,
//!     and the published `ControlPlaneSnapshot` `VirtualKeyAuthenticator` now
//!     reads instead of a static `KeySet` -- see
//!     `internal-docs/wp-50-3b-store-design-brief.md`. `redb` and the admin
//!     write API are 3b-ii, not built here. Increment 3c-i ([`spend`]) adds
//!     the spend-budget filter's price table: a pure `(cluster, model)` ->
//!     per-bucket-price lookup and the integer-micro-dollar cost function
//!     over one request's `usage::TokenUsage` -- see
//!     `internal-docs/wp-50-3c-spend-budgets.md`. No accumulation, no
//!     enforcement, and no `HttpFilter` yet; those are 3c-ii/iii.

pub mod auth;
pub mod auth_filter;
pub mod body_rewrite;
pub mod body_rewrite_filter;
pub mod control;
pub mod model_authz;
pub mod model_authz_filter;
pub mod spend;
pub mod spend_limit_filter;
pub mod token_limit;
pub mod token_limit_filter;
pub mod usage;
pub mod usage_filter;
