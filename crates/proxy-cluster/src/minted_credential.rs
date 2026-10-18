//! Minted provider credentials: an OAuth2 access token that a provider cluster
//! mints with the JWT-bearer grant (RFC 7523) and refreshes off the request
//! path (ADR-0005, amendment 2026-10-17). Workers read the published token and
//! never fetch, mint or wait for one.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;

use crate::ClusterName;

/// At most one warning per window for a repeated failure; the rest are counted.
const WARN_WINDOW: Duration = Duration::from_secs(60);

/// One published access token. The header value is marked sensitive, and no
/// `Debug` impl prints it.
struct MintedToken {
    bearer: http::HeaderValue,
    expires_at: Instant,
}

/// The cluster-owned state behind an `OAuth2JwtBearer` credential: the last
/// published token and log suppression.
pub struct MintedCredential {
    cluster: ClusterName,
    current: ArcSwapOption<MintedToken>,
    refusal_warnings: WarnLimiter,
}

impl std::fmt::Debug for MintedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintedCredential")
            .field("cluster", &self.cluster)
            .field("has_token", &self.current.load().is_some())
            .finish_non_exhaustive()
    }
}

impl MintedCredential {
    pub(crate) fn new(cluster: &str) -> Self {
        Self {
            cluster: cluster.to_string(),
            current: ArcSwapOption::empty(),
            refusal_warnings: WarnLimiter::new(),
        }
    }

    /// The `authorization` value for a request sent at `now`, or `None` when no
    /// token has been minted or the last one has expired. Lock-free; never
    /// blocks and never fetches.
    pub fn bearer(&self, now: Instant) -> Option<http::HeaderValue> {
        let token = self.current.load();
        let token = token.as_ref()?;
        (now < token.expires_at).then(|| token.bearer.clone())
    }

    // The refresher that calls this lands separately from this interface.
    #[allow(dead_code)]
    pub(crate) fn publish(&self, bearer: http::HeaderValue, expires_at: Instant) {
        self.current.store(Some(std::sync::Arc::new(MintedToken {
            bearer,
            expires_at,
        })));
    }

    /// Records one request refused for want of a token. Returns the number of
    /// refusals suppressed since the last warning when the caller should warn
    /// now: at most once a minute per cluster.
    pub fn note_refusal(&self) -> Option<u64> {
        self.refusal_warnings.check()
    }
}

/// Allows one warning per [`WARN_WINDOW`] and counts the rest. Touched only on
/// failure paths, so it costs a healthy request nothing.
struct WarnLimiter {
    origin: Instant,
    /// Milliseconds after `origin` of the last warning, or `u64::MAX` before
    /// the first.
    last_ms: AtomicU64,
    suppressed: AtomicU64,
}

impl WarnLimiter {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
            last_ms: AtomicU64::new(u64::MAX),
            suppressed: AtomicU64::new(0),
        }
    }

    fn check(&self) -> Option<u64> {
        let now = u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX - 1);
        let last = self.last_ms.load(Ordering::Relaxed);
        let due = last == u64::MAX || now.saturating_sub(last) >= WARN_WINDOW.as_millis() as u64;
        // Rust note: `compare_exchange` lets exactly one of several workers that
        // see the window open at once win the warning; the others count.
        if due
            && self
                .last_ms
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            return Some(self.suppressed.swap(0, Ordering::Relaxed));
        }
        self.suppressed.fetch_add(1, Ordering::Relaxed);
        None
    }
}
