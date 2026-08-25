//! Per-worker HTTP/2 upstream connection cache (WP-15 slice A, extended by
//! slice C): keeps a small, bounded *set* of live hyper h2 [`SendRequest`]s
//! per (cluster, address, protocol) instead of exactly one, and hands out
//! clones from whichever member of that set has room, instead of dialing a
//! fresh TCP connection (and TLS handshake, where configured) for every
//! request. hyper's h2 `SendRequest` multiplexes concurrent requests over
//! one connection internally and is cheap to `.clone()`, so the win is still
//! N concurrent requests to one provider costing far fewer than N TCP
//! connections -- just not always exactly 1 any more.
//!
//! ## Why slice A's "exactly one connection" wasn't enough (slice C)
//!
//! A capacity sweep plateaued at exactly 202 concurrent streams no matter
//! how much load was offered, because the peer (any real h2 server,
//! including hyper's own, whose server default is
//! `max_concurrent_streams: 200`, `hyper-1.11.0/src/proto/h2/server.rs:69`)
//! caps how many streams *one* connection may carry at once, and slice A
//! cached exactly one connection per key. h1 hit no such ceiling (its own
//! pool dials a fresh connection per stream), so h2 pooling was costing up
//! to 5x peak concurrency versus h1 for the identical workload.
//!
//! The fix is a bounded *set* of connections (see [`MAX_CONNECTIONS_PER_KEY`])
//! plus our own accounting of how many streams are in flight on each one
//! (see [`SOFT_STREAMS_PER_CONNECTION`], [`StreamGuard`]) -- **not** hyper's
//! `SendRequest::poll_ready`/`is_ready`/`is_closed`. Read those three
//! methods in `hyper-1.11.0/src/client/conn/http2.rs` before reaching for
//! them here: for the h2 client they only ever report whether the
//! connection is *closed*, never whether it currently has spare stream
//! capacity (that real backpressure exists, but it lives entirely inside
//! the spawned connection-driving task -- `proto::h2::client::ClientTask`
//! polls the underlying `h2::client::SendRequest::poll_ready` itself, and
//! only pulls the next queued request off its internal channel once a real
//! slot frees). Excess sends past the peer's true limit don't fail; they
//! queue invisibly inside that task -- which is exactly the fixed-slot-queue
//! symptom the sweep measured (TTFT jumping to one full stream duration).
//! So this module tracks its own conservative "how busy does *this* pool
//! think this connection is" counter to decide when to prefer a different
//! (or new) connection; hyper's real per-connection queue is still what
//! ultimately keeps everything safe if that guess runs a little high.
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

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use bytes::Bytes;
use hyper::body::{Body, Frame, SizeHint};
use hyper::client::conn::http2::SendRequest;
use proxy_cluster::{HttpConnPool, PoolError, UpstreamProtocol};

use crate::codec::{handshake_upstream_http2, send_on_http2, UpstreamCodecError};
use crate::handler::{local_boxed, BodyError, HttpRequestParts, HttpResponseParts, StreamBody};

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

/// How many streams this cache will let itself *prefer* piling onto one
/// connection before it goes looking for another. Not a real limit --
/// nothing here can observe the peer's actual `max_concurrent_streams`
/// (this module's doc explains why hyper's public h2 client API doesn't
/// expose it) -- just our own conservative guess for "probably has room",
/// used only to decide which of our own connections to route a request to.
/// 100 is not invented for this: it's `DEFAULT_INITIAL_MAX_SEND_STREAMS`,
/// the exact value hyper's own h2 client assumes for a connection before it
/// has heard a real SETTINGS frame from the peer
/// (`hyper-1.11.0/src/proto/h2/client.rs:61`) -- i.e. the same conservative
/// "this is safe until proven otherwise" number hyper itself already
/// trusts. Once every connection in the set looks this busy,
/// [`UpstreamConnCache::get_or_connect`] dials another rather than queuing
/// everything behind a guess.
///
/// Honest limitation, not a defect: this is a heuristic, and it can be
/// wrong in either direction because nothing here ever learns the peer's
/// *real* advertised limit. Against the hyper server this module's doc
/// measured (which advertises 200), this guess dials a second connection
/// at 100 in-flight streams even though the first connection could actually
/// have carried all 200 -- conservative, not optimal. So this fix does not
/// remove the per-connection ceiling, it multiplies it by
/// [`MAX_CONNECTIONS_PER_KEY`]: roughly 100 -> ~400 for that measured peer,
/// not 100 -> unbounded. A peer that advertises fewer than 100 (unusual;
/// RFC 7540 6.5.2 suggests 100 as a floor, but nothing enforces it) can
/// still see more concurrent leases than it will actually run concurrently
/// on a given connection -- safely, since hyper's own per-connection queue
/// (this module's doc, above) absorbs the excess rather than failing it,
/// just later than an accurate guess would have spread the load.
const SOFT_STREAMS_PER_CONNECTION: usize = 100;

/// The hard cap on how many physical connections one [`ConnKey`] may hold at
/// once. Must be bounded: with no cap, a sustained burst above
/// [`SOFT_STREAMS_PER_CONNECTION`] would dial a fresh connection (and TLS
/// handshake, where configured) per request once every existing connection
/// looked busy -- recreating exactly the connect-per-request cost pooling
/// exists to avoid. 4 is a deliberately small, fixed starting point: the
/// capacity sweep that motivated this module plateaued with ONE connection
/// capped at 200 real concurrent streams (hyper's own server default,
/// `hyper-1.11.0/src/proto/h2/server.rs:69`); four connections, each free to
/// carry however many streams the peer really allows (not just our
/// [`SOFT_STREAMS_PER_CONNECTION`] guess -- see this module's doc), gives
/// several times that ceiling per key while still amortizing the TCP+TLS
/// handshake cost over many requests per connection, and without opening
/// enough parallel connections to itself look like abuse to a peer that
/// caps concurrent connections per client. Not (yet) configurable per
/// cluster; a fixed conservative default is in scope for this slice.
const MAX_CONNECTIONS_PER_KEY: usize = 4;

/// One connection this cache is holding open for a [`ConnKey`], plus our own
/// best guess at how many streams are currently in flight on it -- see
/// [`StreamGuard`] for how that counter is kept honest across the whole
/// request/response lifetime, not just until headers arrive.
struct PooledConn {
    sender: SendRequest<StreamBody>,
    in_flight: Rc<Cell<usize>>,
    /// The S5 `max_connections` slot (WP-15) this physical connection holds
    /// -- moved out of the [`proxy_cluster::UpstreamStream`] `pool.new_stream()`
    /// returned, rather than dropped at the end of `get_or_connect`, so it
    /// lives exactly as long as this cached connection does and releases the
    /// slot only when the connection is evicted (dead-connection `retain`,
    /// `invalidate`, or `clear`). Never read -- it's a pure RAII drop-guard.
    _cb_guard: Option<proxy_cluster::CbGuard>,
}

/// One cache slot: the bounded set of connections currently held for a
/// single [`ConnKey`]. Empty means nobody has successfully dialed this key
/// yet (or every prior occupant died and was cleared).
/// `Rc<tokio::sync::Mutex<_>>`, not a plain `RefCell` -- see
/// [`UpstreamConnCache::get_or_connect`]'s doc for why a real (queueing)
/// lock is required here even though this whole cache never leaves one
/// worker thread.
type Slot = Rc<tokio::sync::Mutex<Vec<PooledConn>>>;

/// A leased h2 sender plus the [`StreamGuard`] that must ride along with
/// whatever response body this stream produces -- see [`Self::send`].
/// Returned by [`UpstreamConnCache::get_or_connect`] instead of a bare
/// `SendRequest` (what slice A returned) so the router can't accidentally
/// send a request without also carrying its stream-accounting guard.
#[derive(Debug)]
pub struct PooledSendRequest {
    sender: SendRequest<StreamBody>,
    guard: StreamGuard,
}

impl PooledSendRequest {
    /// Send `req` over this leased connection and keep this stream counted
    /// as in-flight (see [`StreamGuard`]) for as long as the *response body*
    /// lives, not just until `codec::send_on_http2`'s `.await` resolves at
    /// the response head. LLM responses are commonly long-lived SSE streams,
    /// so "in flight" has to mean the whole stream duration or this cache's
    /// accounting would systematically undercount exactly the workload it
    /// was built for.
    ///
    /// Kept here rather than changing `codec::send_on_http2`'s own
    /// signature, so `codec.rs` stays pool-agnostic -- the same split slice
    /// A already drew between "dial" (`handshake_upstream_http2`) and "send"
    /// (`send_on_http2`).
    pub async fn send(
        self,
        req: HttpRequestParts,
    ) -> Result<HttpResponseParts, UpstreamCodecError> {
        let PooledSendRequest { sender, guard } = self;
        let mut response = send_on_http2(sender, req).await?;
        response.body = guard.attach(response.body);
        Ok(response)
    }
}

/// RAII stream-accounting handle. Created by
/// [`UpstreamConnCache::get_or_connect`] (via `lease`, incrementing
/// [`PooledConn::in_flight`] there and then), and decremented on `Drop`
/// -- whichever way that happens: the response body read to completion, an
/// early `?` before one was ever produced, or the body simply being dropped
/// because the downstream client went away mid-stream. Every one of those is
/// "this stream is no longer in flight" for this cache's purposes, and
/// `Drop` fires on all of them uniformly.
///
/// Rust note: `Cell<usize>`, not an atomic or a `Mutex` -- this whole cache
/// never leaves its worker's OS thread (ADR-0003, the same reasoning
/// `UpstreamConnCache`'s own doc gives for using `RefCell` over its map), so
/// there's no cross-thread race to guard against, only interior mutability
/// through a shared `Rc`.
#[derive(Debug)]
struct StreamGuard {
    in_flight: Rc<Cell<usize>>,
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.in_flight.set(self.in_flight.get().saturating_sub(1));
    }
}

impl StreamGuard {
    /// Wrap `body` so this guard's decrement fires exactly when `body` is
    /// dropped, instead of wherever `self` would otherwise have gone out of
    /// scope -- see [`GuardedBody`].
    fn attach(self, body: StreamBody) -> StreamBody {
        local_boxed(GuardedBody {
            inner: body,
            _guard: self,
        })
    }
}

/// A [`Body`] combinator that just delegates to `inner`, holding `_guard`
/// alive for exactly as long as the body itself is -- see
/// `StreamGuard::attach`. Same shape as `router::guarded::GuardedBody`
/// (not reused directly: that one is private to the `router` module, and
/// this module owns its own guard type rather than adding a `proxy-http`
/// visibility hole to reach it).
///
/// Rust note: `inner` is a [`StreamBody`] (`Pin<Box<dyn Body<..>>>`, which
/// is `Unpin` regardless of what it boxes -- the box itself owns the pin),
/// and `_guard: StreamGuard` is a plain owned value with no self-references
/// (so it's `Unpin` too). That makes `GuardedBody` as a whole `Unpin`, so
/// `poll_frame` below can use `self.get_mut()` to reach `&mut self.inner`
/// directly -- no manual (`unsafe`) pin projection, and no need for the
/// `pin-project`/`pin-project-lite` crate. `unsafe` is denied
/// workspace-wide, so this field shape is what makes the safe projection
/// possible at all.
struct GuardedBody {
    inner: StreamBody,
    _guard: StreamGuard,
}

impl Body for GuardedBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

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

    /// Return a leased h2 sender for `key`: a clone from whichever cached
    /// connection currently looks least busy, dialing a fresh one first if
    /// none exist yet, none has room under [`SOFT_STREAMS_PER_CONNECTION`],
    /// or the set is empty because every prior occupant died (hazard 2:
    /// GOAWAY / upstream-initiated close). On a failed dial or handshake the
    /// cache is left holding no *new* entry for `key` (hazard 4) -- the
    /// caller's own retry, if any, or the next request simply tries again
    /// rather than getting stuck behind a poisoned one. Never returns an
    /// error purely because every existing connection is busy: once the set
    /// is at [`MAX_CONNECTIONS_PER_KEY`], this hands out the least-loaded
    /// member anyway and lets hyper's own per-connection queue (see this
    /// module's doc) absorb the rest, exactly as slice A's single connection
    /// already did for everything past its one connection's real capacity.
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
    /// open exactly one connection` test, which still holds: under
    /// [`SOFT_STREAMS_PER_CONNECTION`] load this still converges on one
    /// connection). The lock is scoped to one key (`Rc`-shared per `ConnKey`
    /// entry, not one lock for the whole cache), so two different clusters'
    /// dials never wait on each other, and it's held for this whole call
    /// (lookup, and dial if needed) so no two concurrent callers for the
    /// same key ever both decide to dial at once.
    pub async fn get_or_connect(
        &self,
        key: ConnKey,
        pool: &dyn HttpConnPool,
    ) -> Result<PooledSendRequest, PoolError> {
        let slot: Slot = self
            .slots
            .borrow_mut()
            .entry(key)
            .or_insert_with(|| Rc::new(tokio::sync::Mutex::new(Vec::new())))
            .clone();

        let mut conns = slot.lock().await;

        // Hazard 2, generalized to a set: drop every dead connection up
        // front so a stale one is never picked as "least loaded" nor
        // counted against the cap below.
        conns.retain(|c| !c.sender.is_closed());

        // 1. Prefer whichever existing connection looks least busy, as long
        // as it's under our own soft target -- see that constant's doc for
        // why this is our own bookkeeping, not a real signal from hyper.
        if let Some(conn) = conns
            .iter()
            .filter(|c| c.in_flight.get() < SOFT_STREAMS_PER_CONNECTION)
            .min_by_key(|c| c.in_flight.get())
        {
            return Ok(lease(conn));
        }

        // 2. Every existing connection (if any) looks busy -- dial one more,
        // as long as the set is still under the hard cap on how many
        // physical connections this key is allowed to hold.
        if conns.len() < MAX_CONNECTIONS_PER_KEY {
            // Rust note: destructure rather than binding `upstream` whole --
            // `upstream.io` moves into `handshake_upstream_http2` below and
            // `upstream.cb_guard` must survive that move to ride into the
            // `PooledConn` we push, so both fields need to come out
            // independently instead of through a struct that would otherwise
            // still be holding the guard when `io` is consumed.
            let proxy_cluster::UpstreamStream { io, cb_guard } = pool.new_stream().await?;
            // A handshake failure is folded into `PoolError::TlsHandshake`:
            // there's no dedicated pool-error variant for "connected, but
            // the h2 preface/settings exchange failed" (`PoolError` lives in
            // `proxy-cluster`, out of scope this batch), and it belongs in
            // the same "never got a usable connection" bucket the retry
            // engine already treats a real TLS handshake failure as
            // (`AttemptOutcome::from_pool_error`).
            let sender = handshake_upstream_http2(io)
                .await
                .map_err(|err| PoolError::TlsHandshake(std::io::Error::other(err)))?;
            conns.push(PooledConn {
                sender,
                in_flight: Rc::new(Cell::new(0)),
                _cb_guard: cb_guard,
            });
            let conn = conns.last().expect("just pushed one line above");
            return Ok(lease(conn));
        }

        // 3. At the cap and everything looks busy: never fail purely
        // because of that -- hand out the least-loaded connection anyway.
        // hyper's own per-connection queue still won't drop or reject the
        // request; it queues internally until a real stream slot frees,
        // exactly like slice A's single connection did for everything past
        // its own real capacity.
        let conn = conns
            .iter()
            .min_by_key(|c| c.in_flight.get())
            .expect("MAX_CONNECTIONS_PER_KEY > 0, so the set is non-empty by branch 2");
        Ok(lease(conn))
    }

    /// Evict every cached connection for `key`, if any. For a caller that
    /// just observed a send failure on a sender it got from this cache and
    /// wants the next request/retry to redial rather than risk getting
    /// handed the same now-suspect connection again before its
    /// `is_closed()` catches up.
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

/// Lease one stream on `conn`: increments its in-flight counter and returns
/// a sender clone paired with the [`StreamGuard`] that decrements it again
/// once the caller is done -- see [`PooledSendRequest::send`].
fn lease(conn: &PooledConn) -> PooledSendRequest {
    conn.in_flight.set(conn.in_flight.get() + 1);
    PooledSendRequest {
        sender: conn.sender.clone(),
        guard: StreamGuard {
            in_flight: conn.in_flight.clone(),
        },
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

    /// Same shape as [`spawn_counting_h2_upstream`], but the server
    /// advertises a deliberately small, explicit `max_concurrent_streams`
    /// (rather than hyper's own server default of 200, far too large to
    /// exercise in a fast unit test), and holds every request open for
    /// `hold` before responding, so a batch of requests offered concurrently
    /// actually overlaps in wall-clock time on the wire instead of each one
    /// finishing before the next is even dialed. Tracks, alongside the
    /// connection-accept counter, how many requests are concurrently being
    /// held (`concurrent`) and the highest that ever reached
    /// (`max_concurrent_seen`) -- what
    /// `more_concurrent_requests_than_one_connections_stream_limit_still_run_concurrently`
    /// asserts against to prove real streams ran concurrently across
    /// connections, not serialized behind hyper's per-connection queue on a
    /// single cached connection.
    async fn spawn_h2_upstream_with_stream_limit(
        max_concurrent_streams: u32,
        hold: std::time::Duration,
    ) -> (
        SocketAddr,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let concurrent = Arc::new(AtomicUsize::new(0));
        let max_concurrent_seen = Arc::new(AtomicUsize::new(0));
        let accepted_clone = accepted.clone();
        let concurrent_clone = concurrent.clone();
        let max_concurrent_seen_clone = max_concurrent_seen.clone();
        tokio::task::spawn_local(async move {
            loop {
                let (io, _peer) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                accepted_clone.fetch_add(1, Ordering::SeqCst);
                let io = TokioIo::new(io);
                let concurrent = concurrent_clone.clone();
                let max_concurrent_seen = max_concurrent_seen_clone.clone();
                tokio::task::spawn_local(async move {
                    let service = service_fn(move |_req: Request<Incoming>| {
                        let concurrent = concurrent.clone();
                        let max_concurrent_seen = max_concurrent_seen.clone();
                        async move {
                            // Rust note: `fetch_add` returns the PREVIOUS
                            // value, so `+ 1` is this request's own
                            // contribution to the count -- and
                            // `fetch_max` (not a separate load+compare) is
                            // what makes the "highest ever seen" update
                            // race-free against other concurrently
                            // in-flight requests doing the same thing.
                            let now = concurrent.fetch_add(1, Ordering::SeqCst) + 1;
                            max_concurrent_seen.fetch_max(now, Ordering::SeqCst);
                            tokio::time::sleep(hold).await;
                            concurrent.fetch_sub(1, Ordering::SeqCst);
                            Ok::<_, std::convert::Infallible>(
                                hyper::Response::builder()
                                    .status(StatusCode::OK)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http2::Builder::new(LocalExec)
                        .max_concurrent_streams(max_concurrent_streams)
                        .serve_connection(io, service)
                        .await;
                });
            }
        });
        (addr, accepted, concurrent, max_concurrent_seen)
    }

    fn plaintext_pool(addr: SocketAddr) -> ConnectPool {
        // Generous on purpose: these tests exercise the CACHE, not the dial
        // budget. `connect_timeout` has its own tests in `proxy-cluster`, and
        // a tight value here would only add timing flake to tests that are
        // about connection reuse.
        ConnectPool::new(
            addr,
            Arc::new(RawTransportSocket),
            addr.ip().to_string(),
            std::time::Duration::from_secs(30),
            proxy_cluster::CircuitBreakerState::default(),
        )
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

                sender_a
                    .send(get_request())
                    .await
                    .expect("cluster-a request");
                sender_b
                    .send(get_request())
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
                sender1.send(get_request()).await.expect("first request");

                let sender2 = cache
                    .get_or_connect(key, &pool)
                    .await
                    .expect("second connect (should reuse)");
                sender2.send(get_request()).await.expect("second request");

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
                sender
                    .send(get_request())
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
                sender1.send(get_request()).await.unwrap();
                assert_eq!(accepted.load(Ordering::SeqCst), 1);

                cache.clear();

                let sender2 = cache.get_or_connect(key, &pool).await.unwrap();
                sender2.send(get_request()).await.unwrap();
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
                sender1.send(get_request()).await.unwrap();
                assert_eq!(accepted.load(Ordering::SeqCst), 1);

                cache.invalidate(&key);

                let sender2 = cache.get_or_connect(key, &pool).await.unwrap();
                sender2.send(get_request()).await.unwrap();
                assert_eq!(accepted.load(Ordering::SeqCst), 2);
            })
            .await;
    }

    /// WP-15 slice C's own motivating regression test: a peer that only
    /// allows `PEER_LIMIT` concurrent streams on one connection must not cap
    /// this cache's *total* achievable concurrency at `PEER_LIMIT` once
    /// demand exceeds it -- the exact shape of the measured bug (a real
    /// capacity sweep plateaued at 202 concurrent streams against a peer
    /// whose real limit was 200, because slice A cached exactly one
    /// connection). `PEER_LIMIT` here is deliberately tiny (2, not 200) so
    /// this test proves the same property in milliseconds instead of
    /// needing hundreds of real sockets.
    #[tokio::test(flavor = "current_thread")]
    async fn more_concurrent_requests_than_one_connections_stream_limit_still_run_concurrently() {
        LocalSet::new()
            .run_until(async {
                const PEER_LIMIT: u32 = 2;
                // Small, but not so small that the mock upstream's own
                // `hold` sleep stops dominating scheduling noise: with
                // `SOFT_STREAMS_PER_CONNECTION` (100) streams funneled
                // `PEER_LIMIT` at a time through the first connection, the
                // whole test takes roughly
                // `SOFT_STREAMS_PER_CONNECTION / PEER_LIMIT * hold`.
                let hold = std::time::Duration::from_millis(5);
                let (addr, accepted, _concurrent, max_concurrent_seen) =
                    spawn_h2_upstream_with_stream_limit(PEER_LIMIT, hold).await;
                let pool = plaintext_pool(addr);
                let cache = UpstreamConnCache::new();
                let key = ConnKey::new("up", addr, UpstreamProtocol::Http2);

                // Warm up the first connection with one full, sequential
                // round trip before anything below leases a second stream
                // on it. This is insurance against a real (if narrow) h2
                // race that has nothing to do with this cache: hyper's h2
                // client assumes up to `SOFT_STREAMS_PER_CONNECTION`
                // streams are safe to open on a *freshly dialed* connection
                // before it has actually processed the peer's SETTINGS
                // frame advertising its real (much smaller, here) limit --
                // a real peer is free to refuse the excess outright (RFC
                // 7540 5.1.2) if a client races ahead of learning that. A
                // completed round trip proves this connection's SETTINGS
                // exchange already happened, so nothing below can race it.
                cache
                    .get_or_connect(key.clone(), &pool)
                    .await
                    .expect("warm-up connect")
                    .send(get_request())
                    .await
                    .expect("warm-up request");
                assert_eq!(accepted.load(Ordering::SeqCst), 1);

                // Lease (but don't yet send on) `SOFT_STREAMS_PER_CONNECTION`
                // more streams, one at a time. Leasing an already-warmed
                // connection is a synchronous accounting step
                // (`get_or_connect`'s branch 1) -- no `.send()` needed to
                // make it count as in-flight, since `StreamGuard` starts
                // counting at lease time, not at send time (see its doc).
                // So this deterministically fills the first connection's
                // in-flight count to exactly the soft cap, without relying
                // on any particular executor interleaving of a concurrent
                // burst to get there.
                let mut leases = Vec::with_capacity(SOFT_STREAMS_PER_CONNECTION + 1);
                for _ in 0..SOFT_STREAMS_PER_CONNECTION {
                    leases.push(
                        cache
                            .get_or_connect(key.clone(), &pool)
                            .await
                            .expect("phase-1 connect"),
                    );
                }
                assert_eq!(
                    accepted.load(Ordering::SeqCst),
                    1,
                    "still exactly one connection while at (not over) the soft cap"
                );

                // The 101st lease is deterministically the one that tips
                // `get_or_connect` into dialing a second connection (branch
                // 2 -- see its doc): every existing connection (just the
                // first) is now at its soft cap. Leased alone, same no-race
                // reasoning as the warm-up above -- a connection's very
                // first stream is always safe regardless of whether its
                // SETTINGS have landed yet, since one stream can never
                // exceed any real peer limit >= 1.
                leases.push(
                    cache
                        .get_or_connect(key, &pool)
                        .await
                        .expect("probe connect"),
                );
                // Not asserted here: `accepted` can still legitimately read
                // 1 at this exact point even though the second connection
                // was just dialed -- `pool.new_stream().await` only proves
                // the *client* side of the TCP handshake completed, not
                // that the mock upstream's own `spawn_local` accept loop
                // (a separate, cooperatively-scheduled task on this same
                // single-threaded `LocalSet`) has actually been polled yet
                // to record it. The assertion below, after a real round
                // trip has gone over the connection, doesn't have that race.

                // Now actually send on all 101 leases concurrently. Both
                // connections are already warmed -- the first via the
                // sequential round trip above, the second trivially since
                // it's only ever asked to carry this one probe stream -- so
                // this is where the real overlap the fix exists for gets
                // exercised: the first connection can only ever really run
                // `PEER_LIMIT` of its 100 queued streams at once (hyper's
                // own per-connection queue absorbs the rest, never failing
                // them -- see this module's doc), while the second
                // connection's probe runs at the very same time, pushing
                // observed concurrency past `PEER_LIMIT` only because a
                // second connection exists at all to run it on.
                let responses = futures::future::join_all(
                    leases.into_iter().map(|pooled| pooled.send(get_request())),
                )
                .await;

                assert_eq!(responses.len(), SOFT_STREAMS_PER_CONNECTION + 1);
                for resp in &responses {
                    assert!(resp.is_ok(), "a request failed: {:?}", resp.as_ref().err());
                }

                let seen = max_concurrent_seen.load(Ordering::SeqCst);
                assert!(
                    seen > PEER_LIMIT as usize,
                    "observed peer-side concurrency {seen} did not exceed the \
                     single-connection stream limit {PEER_LIMIT} -- requests serialized \
                     behind one connection"
                );

                let opened = accepted.load(Ordering::SeqCst);
                assert!(
                    opened > 1,
                    "expected more than one physical connection to have been dialed, got {opened}"
                );
                assert!(
                    opened <= MAX_CONNECTIONS_PER_KEY,
                    "opened {opened} connections, more than the cache's own cap of \
                     {MAX_CONNECTIONS_PER_KEY}"
                );
            })
            .await;
    }
}
