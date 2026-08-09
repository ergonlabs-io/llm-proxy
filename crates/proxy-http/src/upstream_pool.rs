//! Per-worker HTTP/2 upstream connection cache (WP-15 slice A): keeps one
//! live hyper h2 [`SendRequest`] per (cluster, address, protocol) and hands
//! every concurrent stream to that upstream a clone of it, instead of
//! dialing a fresh TCP connection (and TLS handshake, where configured) for
//! every request. hyper's h2 `SendRequest` multiplexes concurrent requests
//! over one connection internally and is cheap to `.clone()`, so this is the
//! entire win: N concurrent requests to one provider become 1 TCP connection
//! instead of N.
//!
//! h1 is untouched by this slice: it stays connect-per-stream through
//! `proxy_cluster::pool::ConnectPool`, exactly as before (see `router.rs`'s
//! module doc). Keep-alive reuse for h1 has its own hazards (draining the
//! body before reuse, `Connection: close`, idle timeouts) and is WP-15
//! slice B.
//!
//! This cache lives here, in `proxy-http`, and not in `proxy-cluster`
//! alongside [`proxy_cluster::HttpConnPool`], because hyper's h2
//! `SendRequest<StreamBody>` is deliberately `!Send` (`StreamBody` is,
//! ADR-0003 -- see `codec.rs`'s use of `spawn_local`/`LocalExec`), while
//! `HttpConnPool`/`ClusterEntry` are `Send + Sync` and shared across every
//! worker OS thread. A pooled sender can't live in that shared pool; it has
//! to live per worker, where the h1/h2 codec already runs.
//! [`proxy_cluster::pool::ConnectPool`] keeps doing exactly what it does
//! today (dial raw bytes); this cache sits on top of it, worker-side.

use std::cell::RefCell;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::rc::Rc;

use hyper::client::conn::http2::SendRequest;
use proxy_cluster::{HttpConnPool, PoolError, UpstreamProtocol};

use crate::codec::handshake_upstream_http2;
use crate::handler::StreamBody;

/// The cache key -- and a security boundary, not just a lookup convenience.
///
/// The cluster name MUST stay part of this key even though `addr` alone can
/// look like it already disambiguates two upstreams. Two *different*
/// clusters can be configured to point at the very same address with
/// different `transport_socket`s (different TLS trust roots, client certs,
/// SNI) and different per-provider credentials
/// (`ClusterConfig::request_headers_to_add`, WP-35). Dropping `cluster` from
/// this key would let a request routed to cluster B reuse cluster A's
/// already-established h2 connection -- shipping A's TLS identity, and every
/// request sent over that connection afterward, to a destination the config
/// never authorized for it. This is the same class of bug ground rule #6
/// already names twice (provider credentials and `host_rewrite_literal`
/// following the routing decision instead of the connection); a future
/// reader who notices `addr` alone "looks like enough" and removes `cluster`
/// to shrink the key would reopen it a third time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnKey {
    pub cluster: String,
    pub addr: SocketAddr,
    pub protocol: UpstreamProtocol,
}

impl ConnKey {
    pub fn new(cluster: impl Into<String>, addr: SocketAddr, protocol: UpstreamProtocol) -> Self {
        Self {
            cluster: cluster.into(),
            addr,
            protocol,
        }
    }
}

// Rust note: hand-written rather than `#[derive(Hash)]` -- `UpstreamProtocol`
// (defined in `proxy-cluster`, out of scope for this batch) derives
// `PartialEq`/`Eq` but not `Hash`, so a derive here wouldn't compile. It has
// only two variants, so hashing "is this Http2" is equivalent to hashing the
// value itself.
impl Hash for ConnKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.cluster.hash(state);
        self.addr.hash(state);
        matches!(self.protocol, UpstreamProtocol::Http2).hash(state);
    }
}

/// One cache slot. `None` means nobody has successfully dialed this key yet
/// (or the previous occupant died and was cleared). `Rc<tokio::sync::Mutex<_>>`,
/// not a plain `RefCell` -- see [`UpstreamConnCache::get_or_connect`]'s doc
/// for why a real (queueing) lock is required here even though this whole
/// cache never leaves one worker thread.
type Slot = Rc<tokio::sync::Mutex<Option<SendRequest<StreamBody>>>>;

/// Per-worker cache of live HTTP/2 upstream connections, keyed by
/// [`ConnKey`]. Reached via [`worker_conn_cache`]; see that function's doc
/// for why a `thread_local!` and not a field on `RouterFilterFactory`.
///
/// Rust note: the cache's own map is behind a `RefCell`, not a `Mutex` --
/// this whole cache is worker-local (`!Send`/ADR-0003, the same reasoning
/// `FilterChainHandler`'s `request_id_rng` gives for its own `RefCell`), so
/// there is no cross-*thread* contention to guard against, only the
/// single-threaded aliasing rule `RefCell` exists for. Each individual
/// [`Slot`] is the one place this module needs a real async lock -- see
/// below.
pub struct UpstreamConnCache {
    slots: RefCell<HashMap<ConnKey, Slot>>,
}

impl Default for UpstreamConnCache {
    fn default() -> Self {
        Self::new()
    }
}

impl UpstreamConnCache {
    pub fn new() -> Self {
        Self {
            slots: RefCell::new(HashMap::new()),
        }
    }

    /// Return a live h2 sender for `key`: a cloned handle onto the cached
    /// connection if one exists and hasn't gone dead (hazard 2: GOAWAY /
    /// upstream-initiated close), or a freshly dialed-and-handshaken one
    /// otherwise. On a failed dial or handshake the cache is left holding no
    /// entry for `key` (hazard 4) -- the caller's own retry, if any, or the
    /// next request simply tries again from nothing rather than getting
    /// stuck behind a poisoned entry.
    ///
    /// Rust note: the per-key `tokio::sync::Mutex` (not this cache's own
    /// `RefCell`) is what's held across the `.await`s below (dial,
    /// handshake), and that matters even though everything here is
    /// single-threaded. `RefCell` only prevents two pieces of code from
    /// aliasing its contents at the same *instant*; it can't make a second
    /// caller for the same key WAIT for the first one's dial to finish.
    /// Without a real (queueing) lock here, N concurrent requests that all
    /// arrive before any of them has finished dialing would each see
    /// "nothing cached yet" on their first synchronous check and each go
    /// dial their own connection -- exactly the thundering-herd this whole
    /// cache exists to prevent (see the router's `two concurrent requests
    /// open exactly one connection` test). The lock is scoped to one key
    /// (`Rc`-shared per `ConnKey` entry, not one lock for the whole cache),
    /// so two different clusters' dials never wait on each other.
    pub async fn get_or_connect(
        &self,
        key: ConnKey,
        pool: &dyn HttpConnPool,
    ) -> Result<SendRequest<StreamBody>, PoolError> {
        let slot: Slot = self
            .slots
            .borrow_mut()
            .entry(key)
            .or_insert_with(|| Rc::new(tokio::sync::Mutex::new(None)))
            .clone();

        let mut guard = slot.lock().await;
        if let Some(sender) = guard.as_ref() {
            if !sender.is_closed() {
                return Ok(sender.clone());
            }
        }
        // Either nothing was cached yet, or what was is dead -- clear it
        // before dialing so a failed dial below leaves the slot empty, not
        // stale (hazard 4). Concurrent callers for this same key are queued
        // on `slot`'s lock, not racing this dial.
        *guard = None;

        let upstream = pool.new_stream().await?;
        // A handshake failure is folded into `PoolError::TlsHandshake`:
        // there's no dedicated pool-error variant for "connected, but the h2
        // preface/settings exchange failed" (`PoolError` lives in
        // `proxy-cluster`, out of scope this batch), and it belongs in the
        // same "never got a usable connection" bucket the retry engine
        // already treats a real TLS handshake failure as
        // (`AttemptOutcome::from_pool_error`).
        let sender = handshake_upstream_http2(upstream.io)
            .await
            .map_err(|err| PoolError::TlsHandshake(std::io::Error::other(err)))?;

        *guard = Some(sender.clone());
        Ok(sender)
    }

    /// Evict the cached connection for `key`, if any. For a caller that just
    /// observed a send failure on a sender it got from this cache and wants
    /// the next request/retry to redial rather than risk handing out the
    /// same now-suspect sender again before its `is_closed()` catches up.
    pub fn invalidate(&self, key: &ConnKey) {
        self.slots.borrow_mut().remove(key);
    }

    /// Drop every cached connection.
    ///
    /// Nothing calls this in the shipped binary today. The natural trigger
    /// would be "this worker just learned about a new config snapshot", but
    /// there is no such live seam yet: `ConfigPublisher::publish` exists and
    /// `run_listener_manager` does reconcile on it, but in
    /// `crates/proxy/src/main.rs` the publisher is only ever used for
    /// `shutdown()`/`join()` -- there is no SIGHUP handler, admin reload
    /// endpoint, or file watcher that calls `publish()` after boot. The only
    /// callers of `publish` anywhere in the tree are unit tests. Wiring a
    /// real post-boot reload trigger is separate, already-scheduled work.
    /// This is not a silently-unhandled config-swap gap (ground rule #1):
    /// there is no reload path yet for a stale entry to survive, so there is
    /// nothing to get wrong. This method (and [`Self::invalidate`]) exist so
    /// that whoever wires the reload trigger has a correct, already-tested
    /// seam to call into.
    pub fn clear(&self) {
        self.slots.borrow_mut().clear();
    }
}

thread_local! {
    // Rust note: one `UpstreamConnCache` per worker OS thread -- ADR-0003
    // gives every worker its own `current_thread` runtime + `LocalSet`, so a
    // `thread_local!` here really does mean "one per worker", not "one per
    // request" or "one process-wide". `RouterFilterFactory` would be the
    // natural home for this, mirroring `FilterChainHandler`'s
    // `Rc<Vec<AccessLoggerRuntime>>`, but it can't hold it directly: it
    // implements `TerminalFilterInstanceFactory`, which requires
    // `Send + Sync` (config-time factories are built once and used across
    // every worker), and `Rc`/`RefCell` are neither. `thread_local!` is the
    // fallback WP-15's brief calls out for exactly this shape of constraint.
    static WORKER_CONN_CACHE: Rc<UpstreamConnCache> = Rc::new(UpstreamConnCache::new());
}

/// This worker's [`UpstreamConnCache`]. Returns an `Rc` clone (a pointer
/// bump), not a borrow -- a `thread_local!`'s `.with(|t| ...)` can only hand
/// out a reference valid for the duration of that call, and callers here
/// need to hold the cache across `.await` points.
pub fn worker_conn_cache() -> Rc<UpstreamConnCache> {
    WORKER_CONN_CACHE.with(Rc::clone)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::send_on_http2;
    use crate::handler::{local_boxed, DownstreamInfo, HttpRequestParts};
    use bytes::Bytes;
    use http::{HeaderMap, Method, StatusCode, Uri};
    use http_body_util::{BodyExt, Full};
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper::Request;
    use hyper_util::rt::TokioIo;
    use proxy_cluster::pool::ConnectPool;
    use proxy_cluster::transport::RawTransportSocket;
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::task::LocalSet;

    /// Same-shape test-only executor as `codec::LocalExec` -- this one only
    /// needs to exist on the *server* side of these tests.
    #[derive(Clone)]
    struct LocalExec;

    impl<F> hyper::rt::Executor<F> for LocalExec
    where
        F: Future + 'static,
    {
        fn execute(&self, fut: F) {
            tokio::task::spawn_local(fut);
        }
    }

    /// Loopback h2 upstream that accepts connections in a loop, answers every
    /// request `200 OK`, and counts how many TCP connections it has
    /// accepted -- what these tests assert against to prove reuse/isolation.
    /// Must be called from inside a running `LocalSet` (binds synchronously
    /// via `try_into`/`from_std` is avoided; instead this just does the async
    /// bind inline via a tiny block_on-free helper below).
    async fn spawn_counting_h2_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_clone = accepted.clone();
        tokio::task::spawn_local(async move {
            loop {
                let (io, _peer) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                accepted_clone.fetch_add(1, Ordering::SeqCst);
                let io = TokioIo::new(io);
                tokio::task::spawn_local(async move {
                    let service = service_fn(|_req: Request<Incoming>| async move {
                        // Rust note: no `.map_err` needed -- `Full`'s own
                        // `Error` type (`Infallible`) already implements
                        // `std::error::Error`, satisfying hyper's server
                        // body bound directly.
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(StatusCode::OK)
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        )
                    });
                    let _ = hyper::server::conn::http2::Builder::new(LocalExec)
                        .serve_connection(io, service)
                        .await;
                });
            }
        });
        (addr, accepted)
    }

    fn plaintext_pool(addr: SocketAddr) -> ConnectPool {
        ConnectPool::new(addr, Arc::new(RawTransportSocket), addr.ip().to_string())
    }

    fn get_request() -> HttpRequestParts {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::HOST, "localhost".parse().unwrap());
        HttpRequestParts {
            head: crate::filter::RequestHeaders {
                method: Method::GET,
                uri: Uri::from_static("/"),
                headers,
            },
            body: local_boxed(
                Full::new(Bytes::new())
                    .map_err(|infallible: std::convert::Infallible| match infallible {}),
            ),
            downstream: DownstreamInfo::loopback(),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn two_clusters_at_the_same_address_do_not_share_a_connection() {
        // The `ConnKey` security property from this module's doc: two
        // clusters pointed at the very same address must never reuse each
        // other's connection, so a request routed to one can never ride the
        // other's TLS identity/credentials.
        LocalSet::new()
            .run_until(async {
                let (addr, accepted) = spawn_counting_h2_upstream().await;
                let pool = plaintext_pool(addr);
                let cache = UpstreamConnCache::new();

                let key_a = ConnKey::new("cluster-a", addr, UpstreamProtocol::Http2);
                let key_b = ConnKey::new("cluster-b", addr, UpstreamProtocol::Http2);

                let sender_a = cache
                    .get_or_connect(key_a, &pool)
                    .await
                    .expect("cluster-a connects");
                let sender_b = cache
                    .get_or_connect(key_b, &pool)
                    .await
                    .expect("cluster-b connects");

                send_on_http2(sender_a, get_request())
                    .await
                    .expect("cluster-a request");
                send_on_http2(sender_b, get_request())
                    .await
                    .expect("cluster-b request");

                assert_eq!(
                    accepted.load(Ordering::SeqCst),
                    2,
                    "two different clusters at the same address must each get their own connection"
                );
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_second_request_reuses_the_first_connection() {
        LocalSet::new()
            .run_until(async {
                let (addr, accepted) = spawn_counting_h2_upstream().await;
                let pool = plaintext_pool(addr);
                let cache = UpstreamConnCache::new();
                let key = ConnKey::new("up", addr, UpstreamProtocol::Http2);

                let sender1 = cache
                    .get_or_connect(key.clone(), &pool)
                    .await
                    .expect("first connect");
                send_on_http2(sender1, get_request())
                    .await
                    .expect("first request");

                let sender2 = cache
                    .get_or_connect(key, &pool)
                    .await
                    .expect("second connect (should reuse)");
                send_on_http2(sender2, get_request())
                    .await
                    .expect("second request");

                assert_eq!(accepted.load(Ordering::SeqCst), 1);
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_failed_dial_leaves_no_cached_entry() {
        LocalSet::new()
            .run_until(async {
                // Bind, learn the address, then drop the listener so nothing
                // is listening there -- reliably refused on loopback.
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                drop(listener);

                let dead_pool = plaintext_pool(addr);
                let cache = UpstreamConnCache::new();
                let key = ConnKey::new("up", addr, UpstreamProtocol::Http2);

                cache
                    .get_or_connect(key.clone(), &dead_pool)
                    .await
                    .expect_err("nothing is listening yet");

                // A listener now comes up at the SAME address (hazard 4:
                // the failed dial above must not have poisoned the entry).
                let (real_addr, accepted) = spawn_counting_h2_upstream().await;
                let live_pool = plaintext_pool(real_addr);

                let sender = cache
                    .get_or_connect(
                        ConnKey::new("up", real_addr, UpstreamProtocol::Http2),
                        &live_pool,
                    )
                    .await
                    .expect("retrying against a now-live address must succeed cleanly");
                send_on_http2(sender, get_request())
                    .await
                    .expect("request over the fresh connection");
                assert_eq!(accepted.load(Ordering::SeqCst), 1);

                // Hazard 4, checked directly: retrying the SAME key (the
                // dead address never came back up) must still cleanly fail
                // rather than getting stuck behind whatever the first failed
                // dial left behind.
                cache
                    .get_or_connect(key, &dead_pool)
                    .await
                    .expect_err("the dead-address key must still fail cleanly, not hang or panic");
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn clear_forces_every_key_to_redial() {
        LocalSet::new()
            .run_until(async {
                let (addr, accepted) = spawn_counting_h2_upstream().await;
                let pool = plaintext_pool(addr);
                let cache = UpstreamConnCache::new();
                let key = ConnKey::new("up", addr, UpstreamProtocol::Http2);

                let sender1 = cache.get_or_connect(key.clone(), &pool).await.unwrap();
                send_on_http2(sender1, get_request()).await.unwrap();
                assert_eq!(accepted.load(Ordering::SeqCst), 1);

                cache.clear();

                let sender2 = cache.get_or_connect(key, &pool).await.unwrap();
                send_on_http2(sender2, get_request()).await.unwrap();
                assert_eq!(
                    accepted.load(Ordering::SeqCst),
                    2,
                    "clear() must force the next request to dial fresh"
                );
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn invalidate_forces_only_the_named_key_to_redial() {
        LocalSet::new()
            .run_until(async {
                let (addr, accepted) = spawn_counting_h2_upstream().await;
                let pool = plaintext_pool(addr);
                let cache = UpstreamConnCache::new();
                let key = ConnKey::new("up", addr, UpstreamProtocol::Http2);

                let sender1 = cache.get_or_connect(key.clone(), &pool).await.unwrap();
                send_on_http2(sender1, get_request()).await.unwrap();
                assert_eq!(accepted.load(Ordering::SeqCst), 1);

                cache.invalidate(&key);

                let sender2 = cache.get_or_connect(key, &pool).await.unwrap();
                send_on_http2(sender2, get_request()).await.unwrap();
                assert_eq!(accepted.load(Ordering::SeqCst), 2);
            })
            .await;
    }
}
