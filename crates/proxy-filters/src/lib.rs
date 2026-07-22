//! Non-core filters, registered by Envoy extension type URL (or, for Lane H,
//! under `type.llmproxy.dev/...`).
//!
//! Work packages (see IMPLEMENTATION_PLAN.md):
//! - WP-31: cors, local_ratelimit, header mutation.
//! - WP-32: ext_authz, ratelimit (gRPC RLS), ext_proc (client side).
//! - Lane H (LLM layer):
//!   - WP-33: streaming-first guarantees + GenAI observability (TTFT/TPOT).
//!   - WP-34: token metering & token-based rate limiting (budget-store seam).
//!   - WP-35: model routing (body peek -> cluster_header) & provider fallback.
//!   - WP-36: Gateway API Inference Extension endpoint-picker support.
//!   - WP-37: realtime WebSocket sessions (session-pinned routing, frame-aware
//!     token metering, session quotas, Close-frame drains) — Appendix S10.

pub mod usage;
