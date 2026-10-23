//! The admin listener's transport: plain HTTP, or TLS from the snapshot's
//! `admin_tls` (`node.metadata["io.llmproxy.admin_tls"]`, the dialect's
//! `admin.tls`). Envoy's admin has no TLS of its own.
//!
//! Rebuilt the way a data-plane listener rebuilds its TLS factories
//! (`proxy_core::listener`'s accept loop): when the snapshot version changes,
//! the next accepted connection reads the certificate files again, so a
//! `SIGHUP` reload serves a renewed certificate. A rebuild failure resets new
//! connections until a later reload succeeds; it never falls back to plain
//! HTTP.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use proxy_config::ir::{DownstreamTlsSpec, SnapshotVersion};
use proxy_config::ConfigSnapshot;
use proxy_core::tls::{DownstreamTlsFactory, TlsBuildError};

/// Bound on an admin TLS handshake, so a client that stalls mid-handshake
/// does not hold a task forever. The listener default for the same bound.
pub(super) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// `TlsBuildError` context, so a bad file is reported against the field.
const CONTEXT: &str = "admin.tls";

#[derive(Clone)]
pub(super) enum AdminTransport {
    Plain,
    Tls(Arc<DownstreamTlsFactory>),
    /// `admin_tls` is set but its certificate could not be loaded: every new
    /// connection is closed.
    Unavailable,
}

impl AdminTransport {
    fn build(spec: Option<&DownstreamTlsSpec>) -> Result<Self, TlsBuildError> {
        match spec {
            None => Ok(Self::Plain),
            Some(spec) => Ok(Self::Tls(Arc::new(DownstreamTlsFactory::build(
                spec, CONTEXT,
            )?))),
        }
    }
}

/// The transport for the snapshot version it was built from.
pub(super) struct TransportCache {
    transport: AdminTransport,
    version: SnapshotVersion,
    addr: SocketAddr,
    token_set: bool,
}

impl TransportCache {
    /// Builds the boot transport. A certificate that cannot be loaded is an
    /// error, so a bad file fails the start, as it does for a listener.
    pub(super) fn new(
        snapshot: &ConfigSnapshot,
        addr: SocketAddr,
        token_set: bool,
    ) -> Result<Self, TlsBuildError> {
        let transport = AdminTransport::build(snapshot.admin_tls.as_deref())?;
        if matches!(transport, AdminTransport::Plain) {
            warn_if_exposed(addr, token_set);
        }
        Ok(Self {
            transport,
            version: snapshot.version,
            addr,
            token_set,
        })
    }

    /// The transport for `snapshot`, rebuilt when its version changed.
    #[must_use]
    pub(super) fn current(&mut self, snapshot: &ConfigSnapshot) -> AdminTransport {
        if snapshot.version != self.version {
            self.version = snapshot.version;
            let next = AdminTransport::build(snapshot.admin_tls.as_deref()).unwrap_or_else(|err| {
                tracing::warn!(
                    error = %err,
                    "admin server: failed to rebuild TLS after a config change; the admin port \
                     closes every new connection until a reload succeeds"
                );
                AdminTransport::Unavailable
            });
            // Only a change to plain HTTP repeats the warning: a reload that
            // keeps the admin plain is already known to the operator.
            if matches!(next, AdminTransport::Plain)
                && !matches!(self.transport, AdminTransport::Plain)
            {
                warn_if_exposed(self.addr, self.token_set);
            }
            self.transport = next;
        }
        self.transport.clone()
    }
}

/// Plain HTTP on a non-loopback address with the write token set sends the
/// token in clear text. The owner chose this bind, so the admin API serves
/// anyway and says so loudly (AGENTS.md "Fail-open controls"). Without a
/// token every gated route is refused, so nothing secret crosses the wire.
fn warn_if_exposed(addr: SocketAddr, token_set: bool) {
    if token_set && !addr.ip().to_canonical().is_loopback() {
        tracing::warn!(
            "admin.address {addr} is not a loopback address and the admin API has no TLS: \
             LLMPROXY_ADMIN_TOKEN and admin responses cross the network in clear text. Serving \
             it anyway. Set admin.tls (node.metadata[\"io.llmproxy.admin_tls\"] in Envoy mode), \
             bind admin.address to loopback, or put a TLS proxy in front"
        );
    }
}
