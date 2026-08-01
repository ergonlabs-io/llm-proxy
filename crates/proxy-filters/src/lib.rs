//! Non-core filters, registered by Envoy extension type URL (or, for Lane H,
//! under `type.llmproxy.dev/...`).
//!
//! Work packages (see IMPLEMENTATION_PLAN.md):
//! - WP-31: cors, local_ratelimit, header mutation.
//! - WP-32: ext_authz, ratelimit (gRPC RLS), ext_proc (client side).
//! - Lane H (LLM layer):
//!   - WP-33: streaming-first guarantees + GenAI observability (TTFT/TPOT).
//!     [`usage_filter`] wires the WP-34 extractor below into the real encode
//!     path.
//!   - WP-34: token metering & token-based rate limiting (budget-store seam).
//!     [`token_limit`] is the budget limiter itself, increment 1: a pure
//!     library ([`token_limit::BudgetStore`] trait + its in-process impl),
//!     not yet wired into an `HttpFilter` or the config/IR surface.
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

pub mod body_rewrite;
pub mod body_rewrite_filter;
pub mod token_limit;
pub mod usage;
pub mod usage_filter;
