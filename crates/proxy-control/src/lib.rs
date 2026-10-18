//! The control plane: state the request path reads but never owns.
//!
//! - [`control`] and [`control_redis`] hold the `ControlPlaneStore` trait, its
//!   in-memory, redb and Redis implementations, and the published
//!   `ControlPlaneSnapshot` the authenticators read.
//! - [`auth`] is the downstream-authentication core: tenant and key
//!   identities, the virtual-key HMAC authenticator, and the
//!   `AuthenticatorChain`. [`model_authz`] holds per-tenant model grants.
//! - [`spend`] accumulates spend against tenant and key budgets;
//!   [`window_counter`] and [`window_usage`] do the same for token windows,
//!   with [`token_limit`] as the budget library and [`token_usage`] its input.
//! - [`tenant_credential_crypto`] seals BYOK credentials at rest, and
//!   [`reconciliation_age`] reports how stale the reconciled counters are.
//!
//! proxy-filters applies all of this on the request path and re-exports each
//! module under its old `proxy_filters::` path.

pub mod auth;
pub mod control;
pub mod control_redis;
pub mod model_authz;
pub mod reconciliation_age;
pub mod spend;
pub mod tenant_credential_crypto;
pub mod token_limit;
pub mod token_usage;
pub mod window_counter;
pub mod window_usage;
