//! Non-core filters, registered by Envoy extension type URL (or, for the
//! LLM-layer filters, under `type.llmproxy.dev/...`).
//!
//! Envoy-parity filters: [`cors`], [`local_ratelimit`], [`ext_authz`], and
//! header mutation (registered from `proxy-core`).
//!
//! LLM-layer filters and their libraries:
//! - [`usage`] extracts provider token usage; [`usage_filter`] wires it into
//!   the encode path without buffering the response.
//! - [`token_limit`] is the token budget limiter (a pure library with a
//!   budget-store seam); [`token_limit_filter`] wires it into the decode and
//!   encode paths.
//! - [`body_rewrite`] is the bounded request-body prefix scanner and splice
//!   engine, shared by forced usage reporting and body-based model routing;
//!   [`body_rewrite_filter`] wires it into the decode path.
//! - [`auth`] is the pure downstream-authentication core (`Authenticator`
//!   trait, `Principal`, the virtual-key HMAC authenticator, and the
//!   `AuthenticatorChain`); [`jwt_auth`] and [`jwks_refresh`] add JWT
//!   verification and OIDC key refresh; [`auth_filter`] wires them into the
//!   decode path under `type.llmproxy.dev/llmproxy.filters.v0.Authentication`.
//! - [`model_authz`] and [`model_authz_filter`] enforce per-tenant model
//!   allow-lists; the filter must run after `llmproxy.auth` (needs the
//!   tenant) and `llmproxy.body_rewrite` (needs the model).
//! - [`control`] and [`control_redis`] hold the `ControlPlaneStore` trait, its
//!   in-memory, redb and Redis implementations, and the published
//!   `ControlPlaneSnapshot` the authenticators read.
//! - [`pricing`] and [`spend`] provide the rate card and spend accumulation;
//!   [`spend_limit_filter`] enforces per-tenant spend budgets.

pub mod auth;
pub mod auth_filter;
pub mod body_rewrite;
pub mod body_rewrite_filter;
pub mod control;
pub mod control_redis;
pub mod cors;
pub mod ext_authz;
pub mod jwks_refresh;
pub mod jwt_auth;
pub mod local_ratelimit;
pub mod model_authz;
pub mod model_authz_filter;
pub mod model_resolver_filter;
pub mod pricing;
pub mod spend;
pub mod spend_limit_filter;
pub mod tenant_credential_crypto;
pub mod token_limit;
pub mod token_limit_filter;
pub mod usage;
pub mod usage_filter;
pub mod window_counter;
