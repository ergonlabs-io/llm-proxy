//! Async DNS resolution abstraction.
//!
//! `STRICT_DNS`/`LOGICAL_DNS` discovery goes through this trait instead of
//! calling `tokio::net::lookup_host` directly, so unit tests can simulate
//! DNS -- including flapping record sets -- without real network access.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

use futures::future::BoxFuture;

/// Resolves a hostname to its current address set. Async because the real
/// implementation is a network call.
pub trait HostResolver: Send + Sync {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>>;
}

/// The production resolver: wraps `tokio::net::lookup_host`, which performs
/// the platform's normal A/AAAA lookup.
#[derive(Debug, Default)]
pub struct TokioResolver;

impl HostResolver for TokioResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
        Box::pin(async move {
            // Rust note: `lookup_host` wants a `ToSocketAddrs`-shaped input;
            // pairing the hostname with a throwaway port satisfies that --
            // only the IPs from the result are used.
            let addrs = tokio::net::lookup_host((host, 0)).await?;
            Ok(addrs.map(|s| s.ip()).collect())
        })
    }
}

/// An in-memory host -> addresses map for tests: simulates DNS without a
/// network round-trip, and lets tests flap records via [`FakeResolver::set`].
///
/// Rust note: `Mutex` (not `RefCell`) because the trait requires
/// `Send + Sync` -- tests may drive this from an async runtime where the
/// resolver is shared across `.await` points.
#[derive(Debug, Default)]
pub struct FakeResolver {
    records: Mutex<HashMap<String, Vec<IpAddr>>>,
    /// Per-host artificial resolution latency, set via [`FakeResolver::set_delay`]. Empty by default, so callers that
    /// never set it see no change. Lets a test hold a reload mid-resolution and observe another cluster's host set
    /// meanwhile (see `manager.rs`'s `a_slow_dns_cluster_does_not_empty_other_clusters_mid_reload`).
    delays: Mutex<HashMap<String, Duration>>,
}

impl FakeResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed or replace the address set `resolve(host)` returns.
    pub fn set(&self, host: &str, addrs: Vec<IpAddr>) {
        self.records
            .lock()
            .expect("lock poisoned: a holder panicked")
            .insert(host.to_string(), addrs);
    }

    /// Make `resolve(host)` sleep for `delay` before returning its (already
    /// seeded) result. Test-only knob -- see the `delays` field doc.
    pub fn set_delay(&self, host: &str, delay: Duration) {
        self.delays
            .lock()
            .expect("lock poisoned: a holder panicked")
            .insert(host.to_string(), delay);
    }
}

impl HostResolver for FakeResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
        let result = self
            .records
            .lock()
            .expect("lock poisoned: a holder panicked")
            .get(host)
            .cloned()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no fake DNS record for `{host}`"),
                )
            });
        let delay = self
            .delays
            .lock()
            .expect("lock poisoned: a holder panicked")
            .get(host)
            .copied();
        Box::pin(async move {
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }
            result
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fake_resolver_returns_seeded_records() {
        let resolver = FakeResolver::new();
        resolver.set("example.internal", vec![IpAddr::from([10, 0, 0, 1])]);
        let ips = resolver.resolve("example.internal").await.unwrap();
        assert_eq!(ips, vec![IpAddr::from([10, 0, 0, 1])]);
    }

    #[tokio::test]
    async fn fake_resolver_errors_on_unknown_host() {
        let resolver = FakeResolver::new();
        assert!(resolver.resolve("nope.internal").await.is_err());
    }
}
