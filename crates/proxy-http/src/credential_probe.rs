//! The save-time check of a tenant credential (ADR-0007 decision 10).
//!
//! The admin API sends one zero-cost `GET` to a provider cluster with the
//! candidate key before it stores the key. This module holds the seam the
//! admin server calls; the implementation dials through the cluster manager,
//! so the probe uses the cluster's own endpoints, transport and TLS, and the
//! same header handling as a tenant-mode request.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::future::BoxFuture;
use http_body_util::Empty;
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use proxy_cluster::manager::ClusterManager;
use proxy_cluster::{ClusterEntry, LoadBalancerContext, UpstreamProtocol};
use proxy_config::ir::TenantCredentialSlot;

use crate::credential_provider::{CredentialProvider, ProviderCredentials};
use crate::filter::RequestHeaders;
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

/// Probes through the cluster manager: the cluster's own host selection,
/// transport socket and upstream protocol, and the router's own header step.
pub struct ClusterCredentialProbe {
    clusters: Arc<ClusterManager>,
    timeout: Duration,
}

impl ClusterCredentialProbe {
    pub fn new(clusters: Arc<ClusterManager>) -> Self {
        Self::with_timeout(clusters, CREDENTIAL_PROBE_TIMEOUT)
    }

    /// A probe with a shorter bound, for tests; production uses [`Self::new`].
    pub fn with_timeout(clusters: Arc<ClusterManager>, timeout: Duration) -> Self {
        Self { clusters, timeout }
    }
}

impl TenantCredentialProbe for ClusterCredentialProbe {
    fn probe(&self, request: CredentialProbeRequest) -> BoxFuture<'static, CredentialProbeOutcome> {
        // Rust note: the returned future is `'static`, so it cannot borrow
        // `self`; the entry lookup happens now and the future owns the result.
        let entry = self.clusters.cluster(&request.cluster);
        let limit = self.timeout;
        Box::pin(async move {
            let Some(entry) = entry else {
                return CredentialProbeOutcome::Unreachable(format!(
                    "cluster `{}` not found",
                    request.cluster
                ));
            };
            match tokio::time::timeout(limit, send_probe(entry, &request)).await {
                Ok(outcome) => outcome,
                Err(_) => CredentialProbeOutcome::TimedOut,
            }
        })
    }
}

/// Aborts the connection driver when dropped, including when a timeout drops
/// the probe future mid-request. hyper already ends the connection once the
/// sender and the pending response are dropped; this makes the release of
/// the connection and its circuit-breaker slot not depend on that.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Connect, send `GET verify_path`, and return the status of the response
/// head. Failure reasons never include a header value or the secret.
async fn send_probe(
    entry: Arc<dyn ClusterEntry>,
    request: &CredentialProbeRequest,
) -> CredentialProbeOutcome {
    use CredentialProbeOutcome::Unreachable;

    let Some(path) = request.slot.verify_path.as_deref() else {
        return Unreachable("no verify_path".to_owned());
    };
    let Some(selection) = entry.select_host(&LoadBalancerContext::default()) else {
        return Unreachable("no healthy host".to_owned());
    };
    // An aggregate hands back the member that owns the host; that member
    // supplies the transport, protocol and headers (AGENTS.md invariant 6).
    let host = selection.host;
    let entry = selection.member.map_or(entry, |member| member.entry);
    let protocol = entry.upstream_protocol();

    // The router's own per-attempt step: the cluster's static headers, then
    // the operator credential headers cleared and the slot written.
    let Ok(uri) = path.parse::<http::Uri>() else {
        return Unreachable("invalid verify_path".to_owned());
    };
    let mut head = RequestHeaders {
        method: http::Method::GET,
        uri,
        headers: http::HeaderMap::new(),
    };
    let credentials = ProviderCredentials::new(None, entry.request_headers_to_add())
        .with_tenant(&request.slot, &request.secret);
    if credentials.apply(&mut head, &Bytes::new()).await.is_err() {
        return Unreachable("credential could not be applied".to_owned());
    }
    if !head.headers.contains_key(http::header::HOST) {
        let name = host
            .hostname
            .clone()
            .unwrap_or_else(|| host.address.ip().to_string());
        let value = match host.address.port() {
            80 | 443 => name,
            port => format!("{name}:{port}"),
        };
        let Ok(value) = http::HeaderValue::from_str(&value) else {
            return Unreachable("invalid host name".to_owned());
        };
        head.headers.insert(http::header::HOST, value);
    }

    let stream = match entry.http_pool(&host, protocol).new_stream().await {
        Ok(stream) => stream,
        Err(err) => return Unreachable(format!("connect failed: {err}")),
    };
    // Held until the driver task ends so the connection keeps its circuit
    // breaker slot for the whole probe.
    let cb_guard = stream.cb_guard;
    let io = TokioIo::new(stream.io);

    let uri = match protocol {
        UpstreamProtocol::Http2 => {
            // h2 takes `:authority` from the URI, not from `Host`.
            let authority = head
                .headers
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            match format!("http://{authority}{path}").parse::<http::Uri>() {
                Ok(uri) => uri,
                Err(_) => return Unreachable("invalid host name".to_owned()),
            }
        }
        UpstreamProtocol::Http1 => head.uri,
    };
    let mut builder = http::Request::builder().method(head.method).uri(uri);
    if let Some(headers) = builder.headers_mut() {
        *headers = head.headers;
    }
    let Ok(req) = builder.body(Empty::<Bytes>::new()) else {
        return Unreachable("invalid request".to_owned());
    };

    let (result, driver) = match protocol {
        UpstreamProtocol::Http1 => {
            let (mut sender, conn) = match http1::handshake(io).await {
                Ok(parts) => parts,
                Err(err) => return Unreachable(format!("handshake failed: {err}")),
            };
            let driver = AbortOnDrop(tokio::spawn(async move {
                let _guard = cb_guard;
                let _ = conn.await;
            }));
            (sender.send_request(req).await, driver)
        }
        UpstreamProtocol::Http2 => {
            let (mut sender, conn) = match http2::handshake(TokioExecutor::new(), io).await {
                Ok(parts) => parts,
                Err(err) => return Unreachable(format!("handshake failed: {err}")),
            };
            let driver = AbortOnDrop(tokio::spawn(async move {
                let _guard = cb_guard;
                let _ = conn.await;
            }));
            (sender.send_request(req).await, driver)
        }
    };
    // The body is never read; dropping the driver aborts it, which drops the
    // connection and releases the circuit-breaker slot.
    drop(driver);
    match result {
        Ok(response) => CredentialProbeOutcome::Status(response.status()),
        Err(err) => Unreachable(format!("request failed: {err}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_debug_does_not_contain_the_secret() {
        let request = CredentialProbeRequest {
            cluster: "openrouter".to_owned(),
            slot: TenantCredentialSlot {
                provider: "openrouter".to_owned(),
                header: "authorization".to_owned(),
                value_prefix: "Bearer ".to_owned(),
                verify_path: Some("/api/v1/key".to_owned()),
            },
            secret: TenantSecret::new("sk-SENTINEL-secret".to_owned()),
        };
        assert!(!format!("{request:?}").contains("SENTINEL"));
    }
}
