//! The save-time check of a tenant credential (ADR-0007 decision 10).
//!
//! The admin API sends one zero-cost `GET` to a provider cluster with the
//! candidate key before it stores the key. This module holds the seam the
//! admin server calls; the implementation dials through the cluster manager,
//! so the probe uses the cluster's own endpoints, transport and TLS, and the
//! same header handling as a tenant-mode request.

use std::time::Duration;

use futures::future::BoxFuture;
use proxy_config::ir::TenantCredentialSlot;

use crate::tenant_credentials::TenantSecret;

/// How long one probe may take, from connect to response head.
pub const CREDENTIAL_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// One probe: which cluster to dial, and the candidate key.
#[derive(Debug)]
pub struct CredentialProbeRequest {
    /// The provider cluster that carries `slot`.
    pub cluster: String,
    /// The cluster's slot. Its `verify_path` is the path the probe sends.
    pub slot: TenantCredentialSlot,
    /// The candidate key, without the slot's value prefix.
    pub secret: TenantSecret,
}

/// What the provider said, or why it said nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialProbeOutcome {
    /// The provider answered. Only the status is kept: the response body may
    /// describe the key and is never read into a log or a reply.
    Status(http::StatusCode),
    /// No response head within [`CREDENTIAL_PROBE_TIMEOUT`].
    TimedOut,
    /// No usable host, a connect or TLS failure, or a protocol error. The
    /// reason names the failure only; it never contains a header value.
    Unreachable(String),
}

/// Sends a credential probe. `Send + Sync` and `'static` futures, because the
/// admin server runs on the control runtime, not on a worker.
pub trait TenantCredentialProbe: Send + Sync {
    fn probe(&self, request: CredentialProbeRequest) -> BoxFuture<'static, CredentialProbeOutcome>;
}
