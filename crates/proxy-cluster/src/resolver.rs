//! Async DNS resolution abstraction (WP-16 §2).
//!
//! `STRICT_DNS`/`LOGICAL_DNS` discovery goes through this trait instead of
//! calling `tokio::net::lookup_host` directly, so unit tests can simulate
//! DNS -- including flapping record sets -- without real network access.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::Mutex;

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
}

impl FakeResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed or replace the address set `resolve(host)` returns.
    pub fn set(&self, host: &str, addrs: Vec<IpAddr>) {
        self.records.lock().unwrap().insert(host.to_string(), addrs);
    }
}

impl HostResolver for FakeResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
        let result = self
            .records
            .lock()
            .unwrap()
            .get(host)
            .cloned()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no fake DNS record for `{host}`"),
                )
            });
        Box::pin(async move { result })
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
