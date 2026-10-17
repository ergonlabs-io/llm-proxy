//! Per-worker upstream connection caches. h2 connections are multiplexed and
//! bounded per key; h1 connections are reused only after a clean response end.
//! The caches stay in `proxy-http` because their hyper senders are `!Send`.
//!
//! h2 clients expose no way to observe the peer's available stream capacity.
//! The cache uses a conservative in-flight count to spread work across a
//! bounded connection set; hyper's per-connection queue handles excess sends.
//!
//! Connection slots live inside the byte stream, so eviction does not release
//! a slot while an h2 stream still owns the socket. Periodic sweeps remove
//! closed, idle, and removed-endpoint connections. Cluster build IDs in keys
//! prevent reuse across changes to TLS, protocol, or connection budgets.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::{Rc, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use hyper::client::conn::http1::SendRequest as Http1SendRequest;
use hyper::client::conn::http2::SendRequest;
use proxy_cluster::pool::ClusterBuildId;
use proxy_cluster::{ConnectTiming, HttpConnPool, PoolError, UpstreamProtocol, UpstreamStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, MissedTickBehavior};

use crate::codec::{
    handshake_upstream_http1, handshake_upstream_http2, send_on_http2, UpstreamCodecError,
};
use crate::filter::{RequestHeaders, ResponseHeaders};
use crate::handler::{local_boxed, BodyError, HttpRequestParts, HttpResponseParts, StreamBody};

/// Cache identity and security boundary: cluster names prevent sharing
/// connections between providers at the same address, while build IDs prevent
/// reuse across configuration changes to TLS or connection budgets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnKey {
    pub cluster: String,
    pub addr: SocketAddr,
    pub protocol: UpstreamProtocol,
    /// Which build of `cluster` dialed the connection -- see
    /// [`ClusterBuildId`].
    pub build: ClusterBuildId,
}

impl ConnKey {
    pub fn new(
        cluster: impl Into<String>,
        addr: SocketAddr,
        protocol: UpstreamProtocol,
        build: ClusterBuildId,
    ) -> Self {
        Self {
            cluster: cluster.into(),
            addr,
            protocol,
            build,
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
        self.build.hash(state);
    }
}

/// How long a connection may sit with no stream on it before the sweep closes
/// it: Envoy's default for a cluster's upstream connection idle timeout
/// (`internal-docs/envoy-semantics.md` S4, `common_http_protocol_options.idle_timeout`,
/// one hour). That field is rejected in strict mode, so there is nothing to
/// configure and nothing to inherit; this is the value Envoy would apply.
const UPSTREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Sweep interval; stale endpoints are reclaimed promptly without frequent
/// work on otherwise idle workers.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Answers whether an address still belongs to a cluster. It runs during the
/// sweep under the map borrow, so it must be cheap and must not call the cache;
/// unknown clusters are treated as removed.
///
/// Rust note: `Rc<dyn Fn(..)>` is a shared, type-erased closure. `dyn` hides the
/// closure's concrete type so the cache need not be generic over it, and `Rc`
/// (not `Arc`) because every cache is worker-local (ADR-0003).
pub type MembershipOracle = Rc<dyn Fn(&str, SocketAddr) -> bool>;

/// The oracle slot a cache and its sweep task share. `None` means no oracle was
/// set, and the sweep then only reclaims closed and idle-expired connections.
type Membership = Rc<RefCell<Option<MembershipOracle>>>;

/// Whether the endpoint was removed. Draining removed hosts prevents stale
/// sockets from holding cluster-wide connection slots (Envoy S4).
fn endpoint_removed(membership: &Membership, key: &ConnKey) -> bool {
    membership
        .borrow()
        .as_ref()
        .is_some_and(|is_member| !is_member(&key.cluster, key.addr))
}

/// Counts reclaimed connections and empty keys.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct SweepReport {
    /// Connections dropped: closed by the peer, or idle past
    /// [`UPSTREAM_IDLE_TIMEOUT`].
    connections: usize,
    /// Keys removed because no connection was left under them.
    keys: usize,
}

/// Run periodic sweeps while the cache is alive.
///
/// Rust note: the task holds a `Weak`, not an `Rc`. A strong handle in a task
/// that never ends would keep the cache alive for the life of the runtime;
/// with a `Weak`, the loop upgrades on every tick and simply returns once the
/// cache is gone. `spawn_local` (not `spawn`) because the entries are `!Send`
/// (ADR-0003), so the task has to stay on this worker's thread, where the
/// cache already lives.
///
/// `MissedTickBehavior::Delay` so a worker that was stalled does not answer a
/// long stall with a burst of back-to-back sweeps: the next tick is one
/// interval after the one that was just delivered.
fn spawn_sweeper<S: 'static>(
    entries: &Rc<RefCell<S>>,
    membership: &Membership,
    cache: &'static str,
    sweep: fn(&RefCell<S>, Instant, &Membership) -> SweepReport,
) {
    let entries: Weak<RefCell<S>> = Rc::downgrade(entries);
    let membership = membership.clone();
    tokio::task::spawn_local(async move {
        let mut ticks = tokio::time::interval_at(Instant::now() + SWEEP_INTERVAL, SWEEP_INTERVAL);
        ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            ticks.tick().await;
            let Some(entries) = entries.upgrade() else {
                return;
            };
            let report = sweep(&entries, Instant::now(), &membership);
            if report != SweepReport::default() {
                tracing::debug!(
                    cache,
                    connections = report.connections,
                    keys = report.keys,
                    "swept the upstream connection cache"
                );
            }
        }
    });
}

/// Upstream stream that owns its S5 connection slot. For h2, the driver can
/// outlive the cached sender, so eviction must not release the slot while a
/// stream still owns the socket.
///
/// Rust note: fields drop in declaration order, so `io` is dropped (the socket
/// closes) before `_slot` hands the budget back. A waiter that is woken by the
/// release therefore never sees a free slot while the old socket is still open.
/// The `AsyncRead`/`AsyncWrite` impls forward to `io` unchanged, including the
/// vectored-write capability, so hyper batches writes exactly as it would on
/// the bare stream.
struct SlotIo {
    io: proxy_cluster::BoxedUpstreamIo,
    _slot: Option<proxy_cluster::CbGuard>,
}

impl SlotIo {
    /// Take the slot out of `stream` and bind it to the stream's lifetime.
    fn new(stream: UpstreamStream) -> Self {
        let UpstreamStream { io, cb_guard, .. } = stream;
        Self {
            io,
            _slot: cb_guard,
        }
    }
}

impl AsyncRead for SlotIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for SlotIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
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
/// cluster; a fixed conservative default is used.
const MAX_CONNECTIONS_PER_KEY: usize = 4;

/// Cached connection and its in-flight count. Its connection slot stays in
/// the socket (see [`SlotIo`]) until the connection ends.
struct PooledConn {
    sender: SendRequest<StreamBody>,
    activity: Rc<ConnActivity>,
    /// When this connection was dialed; every stream leased from it reports
    /// these values.
    timing: ConnectTiming,
}

impl PooledConn {
    /// Has this connection had no stream on it for the whole of
    /// [`UPSTREAM_IDLE_TIMEOUT`] as of `now`? A connection that is carrying
    /// even one stream is not idle, however long ago it was dialed -- an LLM
    /// response can legitimately stream for longer than the timeout.
    fn idle_expired(&self, now: Instant) -> bool {
        self.activity.in_flight.get() == 0
            && now.saturating_duration_since(self.activity.idle_since.get())
                >= UPSTREAM_IDLE_TIMEOUT
    }
}

/// How busy one cached connection is, shared between its cache entry and every
/// [`StreamGuard`] leased from it.
#[derive(Debug)]
struct ConnActivity {
    in_flight: Cell<usize>,
    /// When `in_flight` last fell to zero, or when the connection was dialed.
    /// Only meaningful while `in_flight` is zero. Stamped when a stream ends
    /// rather than when it starts, so a connection that was busy for hours is
    /// idle for a full timeout *after* its last stream, not instantly.
    idle_since: Cell<Instant>,
}

impl ConnActivity {
    fn new() -> Self {
        Self {
            in_flight: Cell::new(0),
            idle_since: Cell::new(Instant::now()),
        }
    }
}

/// Bounded connection set for one key. The async mutex serializes dials
/// across awaits; see [`UpstreamConnCache::get_or_connect`].
type Slot = Rc<tokio::sync::Mutex<Vec<PooledConn>>>;

/// Leased h2 sender paired with the guard that tracks its response body.
#[derive(Debug)]
pub struct PooledSendRequest {
    sender: SendRequest<StreamBody>,
    guard: StreamGuard,
    timing: ConnectTiming,
}

impl PooledSendRequest {
    /// When the leased connection was dialed, for `US_CX_*` and `US_HS_END`.
    pub fn connect_timing(&self) -> ConnectTiming {
        self.timing
    }

    /// Send `req` over this leased connection and keep this stream counted
    /// as in-flight (see `StreamGuard`) for as long as the *response body*
    /// lives, not just until `codec::send_on_http2`'s `.await` resolves at
    /// the response head. LLM responses are commonly long-lived SSE streams,
    /// so "in flight" has to mean the whole stream duration or this cache's
    /// accounting would systematically undercount exactly the workload it
    /// was built for.
    ///
    /// Kept here rather than changing `codec::send_on_http2`'s own
    /// signature, so `codec.rs` stays pool-agnostic -- the same split the
    /// original design already drew between "dial" (`handshake_upstream_http2`) and "send"
    /// (`send_on_http2`).
    pub async fn send(
        self,
        req: HttpRequestParts,
    ) -> Result<HttpResponseParts, UpstreamCodecError> {
        let PooledSendRequest { sender, guard, .. } = self;
        let mut response = send_on_http2(sender, req).await?;
        response.body = guard.attach(response.body);
        Ok(response)
    }
}

/// RAII handle that decrements the in-flight count when the response body is
/// completed or dropped, including when the downstream disconnects.
///
/// Rust note: `Cell<usize>`, not an atomic or a `Mutex` -- this whole cache
/// never leaves its worker's OS thread (ADR-0003, the same reasoning
/// `UpstreamConnCache`'s own doc gives for using `RefCell` over its map), so
/// there's no cross-thread race to guard against, only interior mutability
/// through a shared `Rc`.
#[derive(Debug)]
struct StreamGuard {
    activity: Rc<ConnActivity>,
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        let remaining = self.activity.in_flight.get().saturating_sub(1);
        self.activity.in_flight.set(remaining);
        // The connection has just become idle: start its idle clock from now.
        // One clock read per connection going idle, not one per stream -- a
        // connection with overlapping streams only reads it for the last one.
        if remaining == 0 {
            self.activity.idle_since.set(Instant::now());
        }
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
/// `Slot` is the one place this module needs a real async lock -- see
/// below.
///
/// The map is behind an `Rc` as well, because the periodic sweep (see this
/// module's "Connection lifetime" section) runs in a task that must reach it
/// without borrowing the cache; that task holds a `Weak`.
pub struct UpstreamConnCache {
    slots: Rc<RefCell<HashMap<ConnKey, Slot>>>,
    /// Whether this cache's sweep task has been started. It starts with the
    /// first connection the cache dials, which is the first moment there is
    /// anything to sweep, and which is also known to be inside a `LocalSet`
    /// (the handshake just spawned onto it).
    sweeper_started: Cell<bool>,
    /// Cluster-membership oracle shared with the sweep task.
    membership: Membership,
}

impl Default for UpstreamConnCache {
    fn default() -> Self {
        Self::new()
    }
}

impl UpstreamConnCache {
    pub fn new() -> Self {
        Self {
            slots: Rc::new(RefCell::new(HashMap::new())),
            sweeper_started: Cell::new(false),
            membership: Membership::default(),
        }
    }

    /// Install the cluster-membership oracle the sweep consults. From the next
    /// sweep on, every connection to an endpoint the oracle reports as no
    /// longer in its cluster is dropped from the cache: idle ones close at
    /// once, and one carrying a stream is left to finish it (the same
    /// mechanism as [`Self::invalidate`]) and closes after.
    pub fn set_membership(&self, oracle: MembershipOracle) {
        *self.membership.borrow_mut() = Some(oracle);
    }

    fn ensure_sweeper(&self) {
        if !self.sweeper_started.replace(true) {
            spawn_sweeper(&self.slots, &self.membership, "h2", sweep_h2);
        }
    }

    /// Return a leased h2 sender for `key`: a clone from whichever cached
    /// connection currently looks least busy, dialing a fresh one first if
    /// none exist yet, none has room under `SOFT_STREAMS_PER_CONNECTION`,
    /// or the set is empty because every prior occupant died (hazard 2:
    /// GOAWAY / upstream-initiated close). On a failed dial or handshake the
    /// key's slot is removed again if it is still empty and no other checkout
    /// holds it (hazard 4), so a failure leaves neither a poisoned entry nor
    /// an empty one for the sweep to find -- the caller's own retry, if any,
    /// or the next request simply tries again. Never returns an
    /// error purely because every existing connection is busy: once the set
    /// is at `MAX_CONNECTIONS_PER_KEY`, this hands out the least-loaded
    /// member anyway and lets hyper's own per-connection queue (see this
    /// module's doc) absorb the rest, exactly as the original single connection
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
    /// `SOFT_STREAMS_PER_CONNECTION` load this still converges on one
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
        // Look up first and clone the key only on a miss, so the common
        // (cached) path allocates nothing.
        let existing = self.slots.borrow().get(&key).cloned();
        let slot: Slot = match existing {
            Some(slot) => slot,
            None => {
                let slot: Slot = Rc::new(tokio::sync::Mutex::new(Vec::new()));
                self.slots.borrow_mut().insert(key.clone(), slot.clone());
                slot
            }
        };

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
            .filter(|c| c.activity.in_flight.get() < SOFT_STREAMS_PER_CONNECTION)
            .min_by_key(|c| c.activity.in_flight.get())
        {
            return Ok(lease(conn));
        }

        // 2. Every existing connection (if any) looks busy -- dial one more,
        // as long as the set is still under the hard cap on how many
        // physical connections this key is allowed to hold.
        if conns.len() < MAX_CONNECTIONS_PER_KEY {
            // The connection's `max_connections` slot moves into the stream
            // (`SlotIo`), so it is released when the socket is, not when this
            // cache happens to evict the entry. A failed handshake drops the
            // stream, and with it the slot, right here.
            // Started before the dial, not after it: a worker whose dials all
            // fail must still sweep.
            self.ensure_sweeper();
            let dialed = async {
                let stream = pool.new_stream().await?;
                let timing = stream.timing;
                let io = SlotIo::new(stream);
                // A handshake failure is folded into `PoolError::TlsHandshake`:
                // there's no dedicated pool-error variant for "connected, but
                // the h2 preface/settings exchange failed" (`PoolError` lives in
                // `proxy-cluster`, out of scope this batch), and it belongs in
                // the same "never got a usable connection" bucket the retry
                // engine already treats a real TLS handshake failure as
                // (`AttemptOutcome::from_pool_error`).
                handshake_upstream_http2(io)
                    .await
                    .map(|sender| (sender, timing))
                    .map_err(|err| PoolError::TlsHandshake(std::io::Error::other(err)))
            }
            .await;
            let (sender, timing) = match dialed {
                Ok(dialed) => dialed,
                Err(err) => {
                    let unused = conns.is_empty();
                    drop(conns);
                    if unused {
                        self.remove_unused_slot(&key, &slot);
                    }
                    return Err(err);
                }
            };
            conns.push(PooledConn {
                sender,
                activity: Rc::new(ConnActivity::new()),
                timing,
            });
            let conn = conns.last().expect("just pushed one line above");
            return Ok(lease(conn));
        }

        // 3. At the cap and everything looks busy: never fail purely
        // because of that -- hand out the least-loaded connection anyway.
        // hyper's own per-connection queue still won't drop or reject the
        // request; it queues internally until a real stream slot frees,
        // exactly like the original single connection did for everything past
        // its own real capacity.
        let conn = conns
            .iter()
            .min_by_key(|c| c.activity.in_flight.get())
            .expect("MAX_CONNECTIONS_PER_KEY > 0, so the set is non-empty by branch 2");
        Ok(lease(conn))
    }

    /// Take `key` out of the map after a failed dial, if `slot` is still the
    /// map's entry for it, holds no connection, and nobody else has a handle to
    /// it. A second checkout parked on the slot's lock holds a clone, so a
    /// reference count above two (the map's plus the caller's) means someone
    /// may be about to dial into it, and removing the key would strand what
    /// they produce. The caller has already released the slot's lock, and this
    /// is synchronous on a single-threaded worker, so nothing can slip in
    /// between the check and the removal.
    fn remove_unused_slot(&self, key: &ConnKey, slot: &Slot) {
        let mut slots = self.slots.borrow_mut();
        let still_ours = slots
            .get(key)
            .is_some_and(|mapped| Rc::ptr_eq(mapped, slot));
        if still_ours && Rc::strong_count(slot) == 2 {
            slots.remove(key);
        }
    }

    /// Evict every cached connection for `key`, if any. For a caller that
    /// just observed a send failure on a sender it got from this cache and
    /// wants the next request/retry to redial rather than risk getting
    /// handed the same now-suspect connection again before its
    /// `is_closed()` catches up.
    ///
    /// Evicting an entry stops new requests using the connection; it does not
    /// cut off a stream already running on it. Such a connection stays open,
    /// and keeps its `max_connections` slot, until that stream ends.
    pub fn invalidate(&self, key: &ConnKey) {
        self.slots.borrow_mut().remove(key);
    }

    /// Drop every cached connection. Active streams retain their sockets and
    /// connection slots until they finish.
    pub fn clear(&self) {
        self.slots.borrow_mut().clear();
    }
}

/// Lease one stream on `conn`: increments its in-flight counter and returns
/// a sender clone paired with the [`StreamGuard`] that decrements it again
/// once the caller is done -- see [`PooledSendRequest::send`].
fn lease(conn: &PooledConn) -> PooledSendRequest {
    let in_flight = &conn.activity.in_flight;
    in_flight.set(in_flight.get() + 1);
    PooledSendRequest {
        sender: conn.sender.clone(),
        guard: StreamGuard {
            activity: conn.activity.clone(),
        },
        timing: conn.timing,
    }
}

/// One pass of the h2 cache's sweep: drop every connection that is closed or
/// has been idle for [`UPSTREAM_IDLE_TIMEOUT`] as of `now` or belongs to an
/// endpoint `membership` says has left its cluster, then every key left with no
/// connection. A free function over the shared map (not a method) so
/// the periodic task can call it through a `Weak` -- see [`spawn_sweeper`].
///
/// A key whose slot a checkout currently holds is skipped, closed connections
/// and all. A checkout holds the slot's lock from its lookup through its dial,
/// so a locked slot is one in use right now, and the checkout prunes closed
/// connections itself. What the sweep must not do is remove the key from the
/// map under it: the connection it is about to dial would be pushed into a
/// slot the map no longer reaches, and the next request would dial again.
/// `try_lock` and not `lock` because the sweep must never wait for a dial.
///
/// Evicted connections are dropped only after the map's `RefCell` borrow has
/// ended, so nothing a destructor does can reach back into the cache while it
/// is borrowed.
fn sweep_h2(
    slots: &RefCell<HashMap<ConnKey, Slot>>,
    now: Instant,
    membership: &Membership,
) -> SweepReport {
    let mut report = SweepReport::default();
    let mut evicted: Vec<PooledConn> = Vec::new();
    slots.borrow_mut().retain(|key, slot| {
        let Ok(mut conns) = slot.try_lock() else {
            return true;
        };
        // Every connection to a removed endpoint goes, in flight or not.
        // Dropping the cache's handle is enough for one carrying a stream:
        // the stream's own sender keeps the socket (and its slot) until it
        // ends, then the connection closes -- the eviction path
        // `invalidate` relies on.
        let removed = endpoint_removed(membership, key);
        let (gone, live): (Vec<PooledConn>, Vec<PooledConn>) = std::mem::take(&mut *conns)
            .into_iter()
            .partition(|conn| removed || conn.sender.is_closed() || conn.idle_expired(now));
        *conns = live;
        report.connections += gone.len();
        evicted.extend(gone);
        let retire = conns.is_empty();
        report.keys += usize::from(retire);
        !retire
    });
    drop(evicted);
    report
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
    // fallback for exactly this shape of constraint.
    static WORKER_CONN_CACHE: Rc<UpstreamConnCache> = Rc::new(UpstreamConnCache::new());
}

/// This worker's [`UpstreamConnCache`]. Returns an `Rc` clone (a pointer
/// bump), not a borrow -- a `thread_local!`'s `.with(|t| ...)` can only hand
/// out a reference valid for the duration of that call, and callers here
/// need to hold the cache across `.await` points.
pub fn worker_conn_cache() -> Rc<UpstreamConnCache> {
    WORKER_CONN_CACHE.with(Rc::clone)
}

/// Install `oracle` on this worker's h2 and h1 caches, so their sweeps drain
/// connections to endpoints that have left their cluster. Call once per
/// worker, at startup.
pub fn set_worker_membership(oracle: MembershipOracle) {
    worker_conn_cache().set_membership(oracle.clone());
    worker_h1_conn_cache().set_membership(oracle);
}

// ---------------------------------------------------------------------
// HTTP/1.1 upstream keep-alive connection reuse.
// ---------------------------------------------------------------------

/// How many IDLE h1 connections [`H1ConnCache`] will hold open, at most, for
/// one [`ConnKey`], waiting for a future request to lease them. Deliberately
/// small: unlike the h2 cache's [`MAX_CONNECTIONS_PER_KEY`] (which bounds
/// *concurrently in-use* connections), every one of these is doing nothing
/// but holding a socket open on the CHANCE the next request happens to be
/// for the same upstream soon -- 8 is enough to smooth out a bursty
/// sequential workload against one provider without accumulating a large
/// number of sockets that just sit there between bursts.
///
/// An idle connection nobody leases again is not left to wait for its peer
/// forever: the periodic sweep closes it after [`UPSTREAM_IDLE_TIMEOUT`], and
/// the slot goes back with the socket if the peer hangs up first (see
/// [`SlotIo`]). The sweep is periodic, though, so a lookup still checks
/// `is_closed()` on every entry it is about to hand out -- a peer can close a
/// connection between two sweeps, and a request must never be sent on one
/// that is already known to be dead.
const MAX_IDLE_PER_KEY: usize = 8;

/// One IDLE h1 connection [`H1ConnCache`] is holding onto between requests --
/// handshaken, currently unleased, and (as far as this cache last checked)
/// still open. Its `max_connections` slot is not a field here: it travels
/// inside the socket (see [`SlotIo`]).
struct IdleH1Conn {
    sender: Http1SendRequest<StreamBody>,
    conn_task: tokio::task::JoinHandle<()>,
    timing: ConnectTiming,
    /// When this connection was returned to the idle queue, for
    /// [`UPSTREAM_IDLE_TIMEOUT`].
    idle_since: Instant,
}

impl IdleH1Conn {
    /// Explicitly tear this idle connection down: abort `conn_task` (which
    /// stops it being polled, dropping the underlying IO and with it the
    /// `max_connections` slot the stream carries), then let `sender` drop
    /// normally as this method returns.
    ///
    /// Rust note: this is a plain consuming method, not a `Drop` impl.
    /// `Drop::drop` only ever gets `&mut self`, and Rust forbids moving a
    /// field out of a value that implements `Drop` at all -- but the REUSE
    /// path (`H1ConnCache::get_or_connect_h1`, below) needs to move
    /// `sender`/`conn_task` out of an `IdleH1Conn` wholesale, by
    /// value, into a [`LeasedH1`]. Giving this type a `Drop` impl would make
    /// that move illegal. An explicit `discard(self)`, called at every site
    /// that decides NOT to keep an idle entry, gets the same guarantee (a
    /// discarded connection is always torn down promptly, never left
    /// dangling) without that conflict -- the reuse path just destructures
    /// the value directly instead, which is only legal because there's no
    /// `Drop` impl in the way.
    fn discard(self) {
        self.conn_task.abort();
    }

    fn idle_expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.idle_since) >= UPSTREAM_IDLE_TIMEOUT
    }
}

/// One pass of the h1 cache's sweep: discard every idle connection that is
/// closed, has waited [`UPSTREAM_IDLE_TIMEOUT`] as of `now`, or belongs to an
/// endpoint `membership` says has left its cluster, then every key
/// left with an empty queue. Only idle connections are ever in this cache, so
/// unlike the h2 sweep there is no "carrying a stream" case to protect: a
/// leased connection is not here to be swept.
///
/// An empty queue is the normal state of a key between requests (a lease
/// pops the connection out), so this is what stops every key that has ever
/// been used from staying in the map forever. Removing it costs nothing
/// when the connection comes back: `H1ReuseBody` recreates the entry.
///
/// As in [`sweep_h2`], discarded connections are dropped after the map's
/// borrow ends.
fn sweep_h1(
    slots: &RefCell<HashMap<ConnKey, VecDeque<IdleH1Conn>>>,
    now: Instant,
    membership: &Membership,
) -> SweepReport {
    let mut report = SweepReport::default();
    let mut evicted: Vec<IdleH1Conn> = Vec::new();
    slots.borrow_mut().retain(|key, idle| {
        let removed = endpoint_removed(membership, key);
        let (gone, live): (VecDeque<IdleH1Conn>, VecDeque<IdleH1Conn>) = std::mem::take(idle)
            .into_iter()
            .partition(|conn| removed || conn.sender.is_closed() || conn.idle_expired(now));
        *idle = live;
        report.connections += gone.len();
        evicted.extend(gone);
        let retire = idle.is_empty();
        report.keys += usize::from(retire);
        !retire
    });
    for conn in evicted {
        conn.discard();
    }
    report
}

/// Per-worker cache of idle HTTP/1.1 connections. A connection is reusable
/// only after its response body ends cleanly; otherwise the next request could
/// be confused with the remainder of the previous response. The sweep reaches
/// the worker-local map through a `Weak` handle.
pub struct H1ConnCache {
    slots: Rc<RefCell<HashMap<ConnKey, VecDeque<IdleH1Conn>>>>,
    /// Whether this cache's sweep task has been started -- see
    /// [`UpstreamConnCache::sweeper_started`].
    sweeper_started: Cell<bool>,
    /// Cluster-membership oracle shared with the sweep task.
    membership: Membership,
}

impl Default for H1ConnCache {
    fn default() -> Self {
        Self::new()
    }
}

impl H1ConnCache {
    pub fn new() -> Self {
        Self {
            slots: Rc::new(RefCell::new(HashMap::new())),
            sweeper_started: Cell::new(false),
            membership: Membership::default(),
        }
    }

    /// Install the cluster-membership oracle the sweep consults; idle
    /// connections to an endpoint it reports as removed are closed on the next
    /// sweep. See [`UpstreamConnCache::set_membership`].
    pub fn set_membership(&self, oracle: MembershipOracle) {
        *self.membership.borrow_mut() = Some(oracle);
    }

    fn ensure_sweeper(&self) {
        if !self.sweeper_started.replace(true) {
            spawn_sweeper(&self.slots, &self.membership, "h1", sweep_h1);
        }
    }

    /// Return a leased h1 connection for `key`: the front of the idle queue
    /// if it holds anything still open, dialing (and handshaking) a fresh
    /// one otherwise. Every dead entry encountered while scanning (`sender.
    /// is_closed()`) is discarded on the way past -- see `IdleH1Conn::discard`
    /// -- rather than left in the queue to be found again.
    ///
    /// Rust note: `self: Rc<Self>`, not `&self` -- this is one of Rust's
    /// stable "arbitrary self types" (alongside plain `self`/`&self`/
    /// `&mut self`/`Box<Self>`/`Arc<Self>`). Taking the `Rc` itself, by
    /// value, is what lets this method hand the SAME `Rc` straight into the
    /// returned [`LeasedH1`] (its `cache` field) without a second,
    /// redundant clone -- `LeasedH1`/`H1ReuseBody` need to push a finished
    /// connection back into this exact cache from `Drop`, long after this
    /// call returns, so they need to own a cheap (`Rc`, pointer-bump) handle
    /// to it. Callers pass `self.h1_cache.clone()` (see `router.rs`'s
    /// attempt loop) rather than `&self.h1_cache`.
    pub async fn get_or_connect_h1(
        self: Rc<Self>,
        key: ConnKey,
        pool: &dyn HttpConnPool,
    ) -> Result<LeasedH1, PoolError> {
        loop {
            let candidate = self
                .slots
                .borrow_mut()
                .get_mut(&key)
                .and_then(VecDeque::pop_front);
            let Some(idle) = candidate else {
                break;
            };
            if idle.sender.is_closed() {
                idle.discard();
                continue;
            }
            let IdleH1Conn {
                sender,
                conn_task,
                timing,
                ..
            } = idle;
            return Ok(LeasedH1 {
                sender,
                conn_task,
                cache: self,
                key,
                timing,
            });
        }

        // Nothing reusable was cached for this key -- dial fresh. The
        // connection's `max_connections` slot moves into the stream
        // (`SlotIo`), so it goes back when the socket does, wherever the
        // connection ends up -- idle in this cache, leased, or discarded.
        let stream = pool.new_stream().await?;
        let timing = stream.timing;
        let io = SlotIo::new(stream);
        // A handshake failure folds into `PoolError::TlsHandshake`, same
        // "never got a usable connection" bucket `UpstreamConnCache::get_or_connect`
        // already folds its own h2 handshake failure into -- see that call
        // site's comment for why there's no dedicated `PoolError` variant
        // for this.
        let (sender, conn_task) = handshake_upstream_http1(io)
            .await
            .map_err(|err| PoolError::TlsHandshake(std::io::Error::other(err)))?;
        self.ensure_sweeper();
        Ok(LeasedH1 {
            sender,
            conn_task,
            cache: self,
            key,
            timing,
        })
    }
}

/// A leased h1 connection, ready to carry exactly one request -- returned by
/// [`H1ConnCache::get_or_connect_h1`] instead of a bare `SendRequest` so the
/// cache/key/task travel with it, for [`Self::send`] to hand to
/// `H1ReuseBody` once the response comes back.
pub struct LeasedH1 {
    sender: Http1SendRequest<StreamBody>,
    conn_task: tokio::task::JoinHandle<()>,
    cache: Rc<H1ConnCache>,
    key: ConnKey,
    timing: ConnectTiming,
}

impl LeasedH1 {
    /// When the leased connection was dialed, for `US_CX_*` and `US_HS_END`.
    /// A reused connection reports its original dial.
    pub fn connect_timing(&self) -> ConnectTiming {
        self.timing
    }

    /// Send `req` over this leased connection and return the response,
    /// head-first with a streaming body -- the reuse-aware counterpart to
    /// `codec::send_upstream_http1`. Builds the outgoing request the same
    /// way that function does, with one deliberate omission: it never sets
    /// `Connection: close`. Sending that header is exactly what made every
    /// prior h1 request connect-per-stream; leaving it off is the entire
    /// point of this cache existing.
    pub async fn send(
        self,
        req: HttpRequestParts,
    ) -> Result<HttpResponseParts, UpstreamCodecError> {
        let LeasedH1 {
            mut sender,
            conn_task,
            cache,
            key,
            timing,
        } = self;

        let RequestHeaders {
            method,
            uri,
            headers,
        } = req.head;
        let mut builder = http::Request::builder().method(method).uri(uri);
        *builder.headers_mut().expect("builder not yet finalized") = headers;
        let request = builder
            .body(req.body)
            .expect("method/uri were already valid; building can't fail here");

        // A connection goes back to the cache on the last byte of its
        // response, which can be before hyper's dispatcher has finished that
        // response and can take another; `send_request` on a dispatcher that
        // is not ready fails. Wait for it. A closed connection fails here, the
        // same as a failed send below.
        if let Err(not_ready) = sender.ready().await {
            conn_task.abort();
            return Err(UpstreamCodecError::Send(not_ready));
        }
        let response = match sender.send_request(request).await {
            Ok(response) => response,
            Err(send_err) => {
                // Never returned to the pool: a failed `send_request` means
                // this connection is suspect (the peer may have closed it
                // right as we wrote, or mid-write of the request itself) --
                // reusing it would be exactly the "poisoned connection"
                // outcome this whole design exists to prevent. Abort the
                // conn task explicitly: that tears the connection down, and
                // the `max_connections` slot goes back with the socket.
                conn_task.abort();
                drop(sender);
                return Err(UpstreamCodecError::Send(send_err));
            }
        };

        // The ONE thing decided up front, from the response head: is the
        // peer even willing to keep this connection open? HTTP/1.0 has no
        // persistent-connection default, and any HTTP version can opt out
        // explicitly with `Connection: close`. This is a necessary
        // condition for reuse, not sufficient -- `H1ReuseBody`'s `Drop`
        // still requires a CLEAN end of stream on top of it (see that type's
        // doc) before actually returning the connection to the cache.
        let reusable = response.version() >= http::Version::HTTP_11
            && !response_has_connection_close(&response);

        let (parts, incoming) = response.into_parts();
        let head = ResponseHeaders {
            status: parts.status,
            headers: parts.headers,
        };
        // Rust note: same adaptation `codec::send_upstream_http1` does for
        // its own response body -- adapt `Incoming`'s error type to
        // `BodyError`, then box it into a `StreamBody` -- before wrapping
        // that (already-erased) body in `H1ReuseBody` below. This keeps
        // `H1ReuseBody` itself generic over "any `StreamBody`" rather than
        // needing to name `Incoming`, and matches `GuardedBody`'s existing
        // shape in this same file (wrap the adapted `StreamBody`, not the
        // raw hyper body).
        let inner: StreamBody = local_boxed(incoming.map_err(|e| BodyError::Upstream(Box::new(e))));

        // An empty body (`Content-Length: 0`, a 204, a HEAD reply) is complete
        // with the head. hyper never polls a body that reports its end, so
        // `poll_frame` would never get to say so.
        let completed = inner.is_end_stream();
        let body: StreamBody = local_boxed(H1ReuseBody {
            inner,
            sender: Some(sender),
            conn_task: Some(conn_task),
            cache,
            key,
            timing,
            reusable,
            completed,
            errored: false,
        });

        Ok(HttpResponseParts {
            head,
            body,
            upgrade: None,
        })
    }
}

/// Does `response`'s `Connection` header carry a `close` token
/// (case-insensitively, tolerating a comma-separated list)? Generic over the
/// body type so it works directly on the still-unsplit
/// `http::Response<hyper::body::Incoming>` `LeasedH1::send` has in hand
/// right after `send_request` returns.
fn response_has_connection_close<B>(response: &http::Response<B>) -> bool {
    response
        .headers()
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("close"))
}

/// Tracks whether the response body ended cleanly and returns the h1
/// connection to the cache only from `Drop`, when its final state is known.
/// `Option` fields allow `Drop` to take ownership of the sender and task.
struct H1ReuseBody {
    inner: StreamBody,
    sender: Option<Http1SendRequest<StreamBody>>,
    conn_task: Option<tokio::task::JoinHandle<()>>,
    cache: Rc<H1ConnCache>,
    key: ConnKey,
    /// Returned with the connection, so its next lease reports the same dial.
    timing: ConnectTiming,
    /// Decided once, from the response head, in `LeasedH1::send` -- see that
    /// method's doc for what makes a response reusable at all.
    reusable: bool,
    /// Set by `poll_frame` the moment `inner` reports a clean end of stream:
    /// `Poll::Ready(None)`, or a frame after which `inner.is_end_stream()`
    /// holds (the last byte of a `Content-Length` body). Never set at all if
    /// the body is dropped before that happens -- which is exactly the "client hung up mid-read, or we
    /// gave up early" case `Drop` below must never reuse.
    completed: bool,
    /// Set by `poll_frame` the moment `inner` reports an error frame. A body
    /// can report a frame error and STILL later reach `Poll::Ready(None)`
    /// depending on the underlying codec, so this flag -- not just
    /// `completed` -- is what `Drop` checks; `completed && errored` must
    /// never be treated as safe to reuse.
    errored: bool,
}

impl Body for H1ReuseBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        // Rust note: same "get_mut + Pin::new on the one non-`Copy` field"
        // shape `GuardedBody::poll_frame` uses in this same file, and sound
        // for the same reason -- `inner` is a `StreamBody`
        // (`Pin<Box<dyn Body<..>>>`, `Unpin` regardless of what it boxes),
        // and every other field here is a plain owned value with no
        // self-references, so `H1ReuseBody` as a whole is `Unpin` and no
        // manual (`unsafe`) pin projection is needed.
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_frame(cx);
        match &poll {
            Poll::Ready(Some(Err(_))) => this.errored = true,
            Poll::Ready(None) => this.completed = true,
            // A `Content-Length` body is complete once its last byte has
            // arrived: hyper's `Incoming` then reports `is_end_stream()`. The
            // downstream h1 writer stops polling there, so the terminal
            // `None` above never comes for such a response, and without this
            // arm the connection was never reused.
            Poll::Ready(Some(Ok(_))) if this.inner.is_end_stream() => this.completed = true,
            _ => {}
        }
        poll
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for H1ReuseBody {
    /// The return-to-pool decision. This is where it has to live, not
    /// `poll_frame`: only `Drop` sees the body's FINAL state -- whether it
    /// was actually drained to `completed`, or abandoned mid-stream --
    /// together with whatever `poll_frame` observed along the way. Deciding
    /// any earlier (e.g. the instant `completed` flips true) would be wrong
    /// in the opposite direction too: nothing stops a caller from reading
    /// past EOF-detection and still holding the body value around, and
    /// nothing here needs it to stop -- `Drop` firing IS "this body is
    /// completely done, one way or the other", which is exactly the
    /// question being answered.
    ///
    /// Rust note: `Drop::drop` only ever gets `&mut self`, so `sender`/
    /// `conn_task` must come out via `Option::take()` rather than a
    /// wholesale destructure (illegal here -- see `IdleH1Conn::discard`'s
    /// doc for the general rule this and that are opposite sides of).
    fn drop(&mut self) {
        let (Some(sender), Some(conn_task)) = (self.sender.take(), self.conn_task.take()) else {
            // `Drop::drop` only ever runs once per value, so this is
            // unreachable in practice -- kept `Option`-typed (rather than
            // plain fields moved out via `unsafe`) specifically so this
            // stays a safe, total match instead of a bare `.unwrap()`.
            return;
        };

        // The ONE safe-to-reuse condition, checked in full: the response
        // body reached a CLEAN end of stream (no error anywhere along the
        // way), the response head said the peer is willing to keep the
        // connection open (`reusable`, decided in `LeasedH1::send`), and the
        // connection hasn't since been observed closed. Every branch below
        // this `if` is a deliberate DISCARD -- see the comment just above
        // `conn_task.abort()` for why each of those cases is unsafe to
        // reuse.
        if self.completed && !self.errored && self.reusable && !sender.is_closed() {
            let mut slots = self.cache.slots.borrow_mut();
            let idle_conns = slots.entry(self.key.clone()).or_default();
            if idle_conns.len() < MAX_IDLE_PER_KEY {
                idle_conns.push_back(IdleH1Conn {
                    sender,
                    conn_task,
                    timing: self.timing,
                    idle_since: Instant::now(),
                });
                return;
            }
            // This key's idle queue is already at `MAX_IDLE_PER_KEY` --
            // drop the borrow before falling through to the discard path
            // below (nothing there needs it, but there's no reason to hold
            // it a moment longer than necessary).
            drop(slots);
        }
        // Every other case lands here, and all of them share one reason:
        // returning THIS connection to the pool risks handing a future
        // request a connection that is still mid-response, in an unknown
        // state, or about to be closed by the peer --
        //   - body dropped before `completed` (client hung up, or a caller
        //     upstream of this one -- e.g. a route `idle_timeout` --  gave
        //     up early): the peer may still be mid-write of this response,
        //     so the next byte on this connection could be more of THIS
        //     response, not the start of a fresh one;
        //   - `errored`: same "unknown mid-response state" reasoning, just
        //     via a decode error instead of an early drop;
        //   - `!reusable`: the peer explicitly said (HTTP/1.0, or
        //     `Connection: close`) that it's closing this connection after
        //     this response, so a reuse attempt would just fail anyway;
        //   - `sender.is_closed()`: already gone, nothing to return;
        //   - the idle queue was full: not unsafe, just no room -- discarded
        //     rather than grown unbounded (see `MAX_IDLE_PER_KEY`'s doc).
        // In every one of these, abort the connection task: that tears the
        // connection down, and the `max_connections` slot goes back with the
        // socket.
        conn_task.abort();
    }
}

thread_local! {
    // Rust note: one `H1ConnCache` per worker OS thread -- same reasoning as
    // `WORKER_CONN_CACHE` just above.
    static WORKER_H1_CONN_CACHE: Rc<H1ConnCache> = Rc::new(H1ConnCache::new());
}

/// This worker's [`H1ConnCache`]. Same "`Rc` clone, not a borrow" shape as
/// [`worker_conn_cache`] -- see that function's doc for why.
pub fn worker_h1_conn_cache() -> Rc<H1ConnCache> {
    WORKER_H1_CONN_CACHE.with(Rc::clone)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::{local_boxed, DownstreamInfo, HttpRequestParts};
    use bytes::Bytes;
    use futures::future::BoxFuture;
    use http::{HeaderMap, Method, StatusCode, Uri};
    use http_body_util::combinators::UnsyncBoxBody;
    use http_body_util::{BodyExt, Full, StreamBody};
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper::Request;
    use hyper_util::rt::TokioIo;
    use proxy_cluster::pool::ConnectPool;
    use proxy_cluster::transport::RawTransportSocket;
    use proxy_cluster::CircuitBreakerState;
    use proxy_config::ir::CircuitBreakerThresholds;
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, OnceLock};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{watch, Notify, Semaphore};
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
            on_upgrade: None,
        }
    }

    /// A key on a given cluster build, identified (as in production) by that
    /// build's connection budget.
    fn key_on(
        cluster: &str,
        addr: SocketAddr,
        protocol: UpstreamProtocol,
        budget: &CircuitBreakerState,
    ) -> ConnKey {
        ConnKey::new(cluster, addr, protocol, ClusterBuildId::of(budget))
    }

    /// The key most tests want: every key built here is on one shared build, so
    /// two keys differ only in what the test varies on purpose (the cluster
    /// name, the address). A test about builds makes its own budgets instead.
    fn test_key(cluster: &str, addr: SocketAddr, protocol: UpstreamProtocol) -> ConnKey {
        static BUILD: OnceLock<CircuitBreakerState> = OnceLock::new();
        key_on(
            cluster,
            addr,
            protocol,
            BUILD.get_or_init(CircuitBreakerState::default),
        )
    }

    /// A connection budget of exactly one that refuses a second dial at once
    /// instead of parking it, so exhaustion shows up as `PoolError::Overflow`
    /// rather than as a wait.
    fn one_connection_budget() -> CircuitBreakerState {
        CircuitBreakerState::from_thresholds(CircuitBreakerThresholds {
            max_connections: 1,
            max_pending_requests: 0,
            ..CircuitBreakerThresholds::ENVOY_DEFAULT
        })
    }

    /// A pool for `addr` that charges `budget`. `ConnectPool` clones the
    /// budget's gauge, so pools for different hosts of one cluster share one
    /// count -- the same way `ClusterHandle::http_pool` builds them.
    fn pool_on(addr: SocketAddr, budget: &CircuitBreakerState) -> ConnectPool {
        ConnectPool::new(
            addr,
            Arc::new(RawTransportSocket),
            addr.ip().to_string(),
            Duration::from_secs(30),
            budget.clone(),
        )
    }

    /// A loopback upstream that answers every request `200` and keeps its
    /// connections open until told otherwise. It reports what it sees on the
    /// wire -- connections accepted, requests read, connections the *client*
    /// closed -- so a test asserts on the peer's view of the proxy instead of
    /// on the cache's internals.
    struct Upstream {
        addr: SocketAddr,
        accepted: Arc<AtomicUsize>,
        shared: ServeState,
        /// Bumping the value makes every connection accepted before the bump
        /// close itself; connections accepted afterwards are unaffected.
        hang_up_signal: watch::Sender<u64>,
        listener_task: tokio::task::JoinHandle<()>,
    }

    /// What an [`Upstream`] holds back until the test releases it.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Hold {
        /// Nothing: every request is answered at once.
        Nothing,
        /// The whole response, head included, so the request is in flight.
        Response,
        /// The end of the response body only: the head goes out at once and
        /// the body then streams, like a long LLM completion. h2 only.
        Body,
    }

    /// What each served connection shares with the test.
    #[derive(Clone)]
    struct ServeState {
        requests: Arc<AtomicUsize>,
        closed_by_client: Arc<AtomicUsize>,
        hold: Hold,
        /// One permit lets one held response (or body) through.
        gate: Arc<Semaphore>,
        hang_up: watch::Receiver<u64>,
    }

    impl Upstream {
        async fn spawn(protocol: UpstreamProtocol) -> Self {
            Self::start(protocol, Hold::Nothing).await
        }

        /// Like [`Self::spawn`], but holds back what `hold` names until the
        /// test calls [`Self::release`].
        async fn spawn_holding(protocol: UpstreamProtocol, hold: Hold) -> Self {
            Self::start(protocol, hold).await
        }

        async fn start(protocol: UpstreamProtocol, hold: Hold) -> Self {
            assert!(
                hold != Hold::Body || protocol == UpstreamProtocol::Http2,
                "only the h2 mock can hold a body back"
            );
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let accepted = Arc::new(AtomicUsize::new(0));
            let (hang_up_signal, hang_up_rx) = watch::channel(0u64);
            let shared = ServeState {
                requests: Arc::new(AtomicUsize::new(0)),
                closed_by_client: Arc::new(AtomicUsize::new(0)),
                hold,
                gate: Arc::new(Semaphore::new(0)),
                hang_up: hang_up_rx,
            };
            let listener_task = tokio::task::spawn_local({
                let accepted = accepted.clone();
                let shared = shared.clone();
                async move {
                    while let Ok((stream, _peer)) = listener.accept().await {
                        accepted.fetch_add(1, Ordering::SeqCst);
                        let conn = shared.clone();
                        match protocol {
                            UpstreamProtocol::Http1 => {
                                tokio::task::spawn_local(conn.serve_h1(stream));
                            }
                            UpstreamProtocol::Http2 => {
                                tokio::task::spawn_local(conn.serve_h2(stream));
                            }
                        }
                    }
                }
            });
            Self {
                addr,
                accepted,
                shared,
                hang_up_signal,
                listener_task,
            }
        }

        fn accepted(&self) -> usize {
            self.accepted.load(Ordering::SeqCst)
        }

        fn requests(&self) -> usize {
            self.shared.requests.load(Ordering::SeqCst)
        }

        fn closed_by_client(&self) -> usize {
            self.shared.closed_by_client.load(Ordering::SeqCst)
        }

        /// Let `n` held-back responses (or bodies) through.
        fn release(&self, n: usize) {
            self.shared.gate.add_permits(n);
        }

        /// Close every connection currently open, from the upstream's side.
        fn hang_up(&self) {
            self.hang_up_signal
                .send_modify(|generation| *generation += 1);
        }

        /// The endpoint disappears: open connections are closed and nothing
        /// listens at the address any more.
        fn go_away(&self) {
            self.listener_task.abort();
            self.hang_up();
        }
    }

    impl ServeState {
        async fn serve_h1(mut self, mut stream: TcpStream) {
            let generation = *self.hang_up.borrow();
            let mut head = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                // One request head at a time. The test requests are bodyless
                // GETs, so the head is the whole request.
                while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                    tokio::select! {
                        _ = self.hang_up.wait_for(|g| *g != generation) => return,
                        read = stream.read(&mut chunk) => match read {
                            Ok(0) | Err(_) => {
                                self.closed_by_client.fetch_add(1, Ordering::SeqCst);
                                return;
                            }
                            Ok(n) => head.extend_from_slice(&chunk[..n]),
                        },
                    }
                }
                head.clear();
                self.requests.fetch_add(1, Ordering::SeqCst);
                if self.hold == Hold::Response {
                    self.gate
                        .acquire()
                        .await
                        .expect("the gate stays open")
                        .forget();
                }
                let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                if stream.write_all(reply).await.is_err() {
                    return;
                }
            }
        }

        async fn serve_h2(mut self, stream: TcpStream) {
            let generation = *self.hang_up.borrow();
            let (requests, gate, hold) = (self.requests.clone(), self.gate.clone(), self.hold);
            let service = service_fn(move |_req: Request<Incoming>| {
                let (requests, gate) = (requests.clone(), gate.clone());
                async move {
                    requests.fetch_add(1, Ordering::SeqCst);
                    let body: UnsyncBoxBody<Bytes, std::convert::Infallible> = match hold {
                        Hold::Nothing => Full::new(Bytes::new()).boxed_unsync(),
                        Hold::Response => {
                            gate.acquire().await.expect("the gate stays open").forget();
                            Full::new(Bytes::new()).boxed_unsync()
                        }
                        // The head is sent as soon as this service returns;
                        // the body is a one-item stream that ends only when
                        // a permit arrives.
                        Hold::Body => StreamBody::new(futures::stream::once(async move {
                            gate.acquire().await.expect("the gate stays open").forget();
                            Ok::<_, std::convert::Infallible>(Frame::data(Bytes::from_static(
                                b"done",
                            )))
                        }))
                        .boxed_unsync(),
                    };
                    Ok::<_, std::convert::Infallible>(
                        hyper::Response::builder()
                            .status(StatusCode::OK)
                            .body(body)
                            .unwrap(),
                    )
                }
            });
            let connection = hyper::server::conn::http2::Builder::new(LocalExec)
                .serve_connection(TokioIo::new(stream), service);
            tokio::pin!(connection);
            tokio::select! {
                // Dropping `connection` on this arm closes the socket.
                _ = self.hang_up.wait_for(|g| *g != generation) => {}
                _ = &mut connection => {
                    self.closed_by_client.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
    }

    /// Both caches behind one interface, so a scenario is written once and run
    /// against h1 and h2.
    struct Caches {
        h2: Rc<UpstreamConnCache>,
        h1: Rc<H1ConnCache>,
    }

    impl Caches {
        fn new() -> Self {
            Self {
                h2: Rc::new(UpstreamConnCache::new()),
                h1: Rc::new(H1ConnCache::new()),
            }
        }

        /// Check a connection out for `key`, send one GET over it, read the
        /// body to its clean end and let go of everything: the connection is
        /// left idle in its cache. Fails only if the checkout itself does (a
        /// refused dial, an exhausted budget).
        async fn round_trip(&self, key: ConnKey, pool: &ConnectPool) -> Result<(), PoolError> {
            let response = match key.protocol {
                UpstreamProtocol::Http2 => {
                    self.h2
                        .get_or_connect(key, pool)
                        .await?
                        .send(get_request())
                        .await
                }
                UpstreamProtocol::Http1 => {
                    self.h1
                        .clone()
                        .get_or_connect_h1(key, pool)
                        .await?
                        .send(get_request())
                        .await
                }
            }
            .expect("the upstream answers");
            response
                .body
                .collect()
                .await
                .expect("the body ends cleanly");
            Ok(())
        }

        fn sweep(&self, protocol: UpstreamProtocol, now: Instant) -> SweepReport {
            match protocol {
                UpstreamProtocol::Http2 => sweep_h2(&self.h2.slots, now, &self.h2.membership),
                UpstreamProtocol::Http1 => sweep_h1(&self.h1.slots, now, &self.h1.membership),
            }
        }
    }

    /// Wait for `condition` by yielding to the scheduler, for effects that
    /// happen in this process (a task being polled) and so need no clock. A
    /// timeout is useless as a hang guard while the clock is frozen -- it
    /// never fires, or fires at once when the runtime idles -- so the
    /// iteration cap is what turns a hang into a failure.
    async fn settle(what: &str, mut condition: impl FnMut() -> bool) {
        for _ in 0..10_000 {
            if condition() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("never settled: {what}");
    }

    /// Wait for `condition` on the real clock, for effects that need the
    /// kernel (a peer noticing a close). The bound only turns a hang into a
    /// failure; nothing asserts on how long the wait took.
    async fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
        let wait = async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        };
        if tokio::time::timeout(Duration::from_secs(10), wait)
            .await
            .is_err()
        {
            panic!("timed out waiting for: {what}");
        }
    }

    /// A pool whose dial waits for the test, so a checkout can be held in the
    /// middle of dialing a key.
    struct GatedPool {
        inner: ConnectPool,
        gate: Arc<Notify>,
    }

    impl HttpConnPool for GatedPool {
        fn new_stream(&self) -> BoxFuture<'static, Result<UpstreamStream, PoolError>> {
            let dial = self.inner.new_stream();
            let gate = self.gate.clone();
            Box::pin(async move {
                gate.notified().await;
                dial.await
            })
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

                let key_a = test_key("cluster-a", addr, UpstreamProtocol::Http2);
                let key_b = test_key("cluster-b", addr, UpstreamProtocol::Http2);

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
                let key = test_key("up", addr, UpstreamProtocol::Http2);

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
                let key = test_key("up", addr, UpstreamProtocol::Http2);

                cache
                    .get_or_connect(key.clone(), &dead_pool)
                    .await
                    .expect_err("nothing is listening yet");
                assert!(
                    cache.slots.borrow().is_empty(),
                    "a failed dial leaves no entry for the key"
                );

                // A listener now comes up at the SAME address (hazard 4:
                // the failed dial above must not have poisoned the entry).
                let (real_addr, accepted) = spawn_counting_h2_upstream().await;
                let live_pool = plaintext_pool(real_addr);

                let sender = cache
                    .get_or_connect(
                        test_key("up", real_addr, UpstreamProtocol::Http2),
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
                assert_eq!(
                    cache.slots.borrow().len(),
                    1,
                    "only the live key is cached; the dead one left nothing behind again"
                );
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
                let key = test_key("up", addr, UpstreamProtocol::Http2);

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
                let key = test_key("up", addr, UpstreamProtocol::Http2);

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

    /// The motivating regression test for the connection set: a peer that only
    /// allows `PEER_LIMIT` concurrent streams on one connection must not cap
    /// this cache's *total* achievable concurrency at `PEER_LIMIT` once
    /// demand exceeds it -- the exact shape of the measured bug (a real
    /// capacity sweep plateaued at 202 concurrent streams against a peer
    /// whose real limit was 200, because the original design cached exactly one
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
                let key = test_key("up", addr, UpstreamProtocol::Http2);

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

    // ------------------------------------------------ connection lifetime --

    /// The reason the slot rides inside the socket. A cluster with a budget of
    /// one connection pools an idle connection to host A; A hangs up on it; a
    /// request is then routed to host B (the cluster's addresses rotated). If
    /// the slot were held until something looked A's key up again -- which
    /// nothing will -- B's dial would overflow for as long as the dead entry
    /// sat in the cache.
    async fn an_idle_connection_closed_by_its_peer_gives_its_slot_back(protocol: UpstreamProtocol) {
        let host_a = Upstream::spawn(protocol).await;
        let host_b = Upstream::spawn(protocol).await;
        let budget = one_connection_budget();
        let caches = Caches::new();
        let key_a = key_on("up", host_a.addr, protocol, &budget);
        let key_b = key_on("up", host_b.addr, protocol, &budget);
        let pool_a = pool_on(host_a.addr, &budget);
        let pool_b = pool_on(host_b.addr, &budget);

        caches
            .round_trip(key_a, &pool_a)
            .await
            .expect("the first dial is within budget");
        assert!(
            budget.try_acquire_connection().is_none(),
            "premise: the idle pooled connection holds the cluster's only slot"
        );
        // Negative control: while A's connection is open, B really cannot dial.
        // Without it this test would also pass if the budget never saturated.
        let refused = caches.round_trip(key_b.clone(), &pool_b).await;
        assert!(
            matches!(refused, Err(PoolError::Overflow)),
            "a dial past the budget must overflow while the idle connection is open, got {refused:?}"
        );

        host_a.hang_up();
        eventually("the closed connection's slot to come back", || {
            budget.try_acquire_connection().is_some()
        })
        .await;

        caches
            .round_trip(key_b, &pool_b)
            .await
            .expect("a dial to the other host succeeds once the closed connection's slot is back");
        assert_eq!(host_b.accepted(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h1_idle_connection_closed_by_its_peer_gives_its_slot_back() {
        LocalSet::new()
            .run_until(an_idle_connection_closed_by_its_peer_gives_its_slot_back(
                UpstreamProtocol::Http1,
            ))
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_idle_connection_closed_by_its_peer_gives_its_slot_back() {
        LocalSet::new()
            .run_until(an_idle_connection_closed_by_its_peer_gives_its_slot_back(
                UpstreamProtocol::Http2,
            ))
            .await;
    }

    /// A keep-alive h1 upstream whose every response carries `body` framed by
    /// `Content-Length`. Returns its address and its accepted-connection count.
    async fn spawn_content_length_h1(body: &'static [u8]) -> (SocketAddr, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = accepted.clone();
        tokio::task::spawn_local(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::task::spawn_local(async move {
                    let mut head = Vec::new();
                    let mut chunk = [0u8; 1024];
                    loop {
                        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                            match stream.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => head.extend_from_slice(&chunk[..n]),
                            }
                        }
                        head.clear();
                        let reply =
                            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                        if stream.write_all(reply.as_bytes()).await.is_err()
                            || stream.write_all(body).await.is_err()
                        {
                            return;
                        }
                    }
                });
            }
        });
        (addr, accepted)
    }

    /// Read `body` the way hyper's downstream h1 writer does for a
    /// `Content-Length` response: frame by frame until `is_end_stream()`, never
    /// asking for the terminal `None`. Then drop it.
    async fn read_like_the_downstream_writer(mut body: crate::handler::StreamBody) {
        while !body.is_end_stream() {
            body.frame()
                .await
                .expect("a frame before the end")
                .expect("a clean frame");
        }
    }

    /// The connection goes back to the cache when the last `Content-Length`
    /// byte arrives, even though the terminal `None` is never polled. The next
    /// lease is taken at once, before hyper's dispatcher may have finished the
    /// previous response, so it must also wait for the dispatcher to be ready.
    #[tokio::test(flavor = "current_thread")]
    async fn a_content_length_response_read_to_its_length_is_reused_at_once() {
        LocalSet::new()
            .run_until(async {
                let (addr, accepted) = spawn_content_length_h1(b"ok").await;
                let cache = Rc::new(H1ConnCache::new());
                let pool = plaintext_pool(addr);
                for n in 1..=3 {
                    let response = cache
                        .clone()
                        .get_or_connect_h1(test_key("up", addr, UpstreamProtocol::Http1), &pool)
                        .await
                        .expect("lease")
                        .send(get_request())
                        .await
                        .unwrap_or_else(|e| panic!("request {n} on the reused connection: {e}"));
                    assert_eq!(response.head.status, StatusCode::OK);
                    read_like_the_downstream_writer(response.body).await;
                }
                assert_eq!(accepted.load(Ordering::SeqCst), 1);
            })
            .await;
    }

    /// An empty `Content-Length: 0` body is complete with the head; hyper
    /// never polls it, and the connection must still be reused.
    #[tokio::test(flavor = "current_thread")]
    async fn an_empty_body_that_is_never_polled_is_reused() {
        LocalSet::new()
            .run_until(async {
                let (addr, accepted) = spawn_content_length_h1(b"").await;
                let cache = Rc::new(H1ConnCache::new());
                let pool = plaintext_pool(addr);
                for _ in 0..2 {
                    let response = cache
                        .clone()
                        .get_or_connect_h1(test_key("up", addr, UpstreamProtocol::Http1), &pool)
                        .await
                        .expect("lease")
                        .send(get_request())
                        .await
                        .expect("response");
                    assert!(response.body.is_end_stream());
                    drop(response);
                }
                assert_eq!(accepted.load(Ordering::SeqCst), 1);
            })
            .await;
    }

    /// The other half of the rule: a body dropped after some of its bytes but
    /// before its last one is not complete, so its connection never enters
    /// the idle queue. (hyper also closes such a connection, so the queue, not
    /// a later dial count, is what shows this guard working.)
    #[tokio::test(flavor = "current_thread")]
    async fn a_content_length_body_dropped_before_its_end_is_not_returned() {
        LocalSet::new()
            .run_until(async {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                tokio::task::spawn_local(async move {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf).await;
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n01234")
                        .await;
                    // Hold the rest back until the client goes away.
                    let _ = stream.read(&mut buf).await;
                });
                let cache = Rc::new(H1ConnCache::new());
                let key = test_key("up", addr, UpstreamProtocol::Http1);
                let mut body = cache
                    .clone()
                    .get_or_connect_h1(key.clone(), &plaintext_pool(addr))
                    .await
                    .expect("lease")
                    .send(get_request())
                    .await
                    .expect("response")
                    .body;
                let first = body.frame().await.expect("a frame").expect("clean");
                assert_eq!(first.data_ref().map(|d| d.len()), Some(5));
                assert!(!body.is_end_stream());
                drop(body);
                let idle = cache.slots.borrow().get(&key).map_or(0, VecDeque::len);
                assert_eq!(
                    idle, 0,
                    "a half-read response must not be returned for reuse"
                );
            })
            .await;
    }

    /// The other side of the slot-travels-with-the-socket rule: a connection
    /// that is *abandoned* mid-request (a per-try timeout, a client that went
    /// away) must not strand its slot either. Before the slot rode in the
    /// socket this was released the instant the request future was dropped;
    /// now it is released when the socket closes, so this pins that hyper does
    /// close an h1 connection whose response nobody is waiting for.
    #[tokio::test(flavor = "current_thread")]
    async fn abandoning_an_h1_request_in_flight_gives_its_slot_back() {
        LocalSet::new()
            .run_until(async {
                // Never answers, so the request is in flight until abandoned.
                let host = Upstream::spawn_holding(UpstreamProtocol::Http1, Hold::Response).await;
                let budget = one_connection_budget();
                let caches = Caches::new();
                let key = key_on("up", host.addr, UpstreamProtocol::Http1, &budget);
                let pool = Rc::new(pool_on(host.addr, &budget));

                let request = tokio::task::spawn_local({
                    let h1 = caches.h1.clone();
                    async move {
                        let leased = h1.get_or_connect_h1(key, &*pool).await?;
                        Ok::<_, PoolError>(leased.send(get_request()).await)
                    }
                });
                eventually("the request to reach the upstream", || host.requests() == 1).await;
                assert!(
                    budget.try_acquire_connection().is_none(),
                    "premise: the connection carrying the request holds the slot"
                );

                request.abort();

                eventually("the abandoned connection's slot to come back", || {
                    budget.try_acquire_connection().is_some()
                })
                .await;
            })
            .await;
    }

    /// Same rule, earlier in the attempt: the router checks a connection out
    /// before it applies the provider credential and rewrites the body, and
    /// returns a local reply if either fails. The leased connection is then
    /// dropped without ever carrying a request, and must not strand its slot.
    #[tokio::test(flavor = "current_thread")]
    async fn dropping_a_leased_h1_connection_that_never_sent_gives_its_slot_back() {
        LocalSet::new()
            .run_until(async {
                let host = Upstream::spawn(UpstreamProtocol::Http1).await;
                let budget = one_connection_budget();
                let caches = Caches::new();
                let key = key_on("up", host.addr, UpstreamProtocol::Http1, &budget);

                let leased = caches
                    .h1
                    .clone()
                    .get_or_connect_h1(key, &pool_on(host.addr, &budget))
                    .await
                    .expect("dial");
                assert!(
                    budget.try_acquire_connection().is_none(),
                    "premise: the leased connection holds the slot"
                );

                drop(leased);

                eventually("the unused connection's slot to come back", || {
                    budget.try_acquire_connection().is_some()
                })
                .await;
            })
            .await;
    }

    /// A key whose endpoint is gone -- its connection closed and nothing
    /// listening any more, as after a DNS answer rotates -- must not stay in
    /// the map. A key that still has a live connection must.
    async fn the_sweep_retires_a_key_whose_endpoint_is_gone(protocol: UpstreamProtocol) {
        let gone = Upstream::spawn(protocol).await;
        let alive = Upstream::spawn(protocol).await;
        let caches = Caches::new();
        let (gone_pool, alive_pool) = (plaintext_pool(gone.addr), plaintext_pool(alive.addr));
        let alive_key = test_key("up", alive.addr, protocol);
        caches
            .round_trip(test_key("up", gone.addr, protocol), &gone_pool)
            .await
            .unwrap();
        caches
            .round_trip(alive_key.clone(), &alive_pool)
            .await
            .unwrap();

        gone.go_away();

        // The client side notices the close asynchronously, so sweep until it
        // has. Everything the sweep removes is accounted for in the report.
        let mut report = SweepReport::default();
        eventually("the sweep to find the closed connection", || {
            report = caches.sweep(protocol, Instant::now());
            report != SweepReport::default()
        })
        .await;
        assert_eq!(
            report,
            SweepReport {
                connections: 1,
                keys: 1
            },
            "the dead connection and the key that held it are both retired, and nothing else"
        );

        caches
            .round_trip(alive_key, &alive_pool)
            .await
            .expect("the live key still works");
        assert_eq!(
            alive.accepted(),
            1,
            "the live key's connection was left alone, so it is reused rather than redialed"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h1_sweep_retires_a_key_whose_endpoint_is_gone() {
        LocalSet::new()
            .run_until(the_sweep_retires_a_key_whose_endpoint_is_gone(
                UpstreamProtocol::Http1,
            ))
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_sweep_retires_a_key_whose_endpoint_is_gone() {
        LocalSet::new()
            .run_until(the_sweep_retires_a_key_whose_endpoint_is_gone(
                UpstreamProtocol::Http2,
            ))
            .await;
    }

    /// Membership oracle for tests: every endpoint is a member except the one
    /// stored in the returned cell.
    fn all_but(removed: &Rc<std::cell::Cell<Option<SocketAddr>>>) -> MembershipOracle {
        let removed = removed.clone();
        Rc::new(move |_cluster, addr| removed.get() != Some(addr))
    }

    fn install_membership(caches: &Caches, oracle: &MembershipOracle) {
        caches.h2.set_membership(oracle.clone());
        caches.h1.set_membership(oracle.clone());
    }

    /// An idle connection to an endpoint that left its cluster is closed by the
    /// next sweep and gives its `max_connections` slot back, an hour before the
    /// idle timeout would. An idle connection to a member endpoint is kept.
    async fn a_removed_endpoints_idle_connection_is_closed_at_the_next_sweep(
        protocol: UpstreamProtocol,
    ) {
        let gone = Upstream::spawn(protocol).await;
        let alive = Upstream::spawn(protocol).await;
        let (gone_budget, alive_budget) = (one_connection_budget(), one_connection_budget());
        let caches = Caches::new();
        let removed = Rc::new(std::cell::Cell::new(None));
        install_membership(&caches, &all_but(&removed));
        let gone_key = key_on("up", gone.addr, protocol, &gone_budget);
        let alive_key = key_on("up", alive.addr, protocol, &alive_budget);
        let alive_pool = pool_on(alive.addr, &alive_budget);
        caches
            .round_trip(gone_key, &pool_on(gone.addr, &gone_budget))
            .await
            .unwrap();
        caches
            .round_trip(alive_key.clone(), &alive_pool)
            .await
            .unwrap();
        assert!(
            gone_budget.try_acquire_connection().is_none(),
            "premise: the idle connection holds the slot"
        );

        let soon = Instant::now() + Duration::from_secs(61);
        assert_eq!(
            caches.sweep(protocol, soon),
            SweepReport::default(),
            "while both endpoints are members nothing is reclaimed"
        );

        removed.set(Some(gone.addr));
        assert_eq!(
            caches.sweep(protocol, soon),
            SweepReport {
                connections: 1,
                keys: 1
            },
            "only the removed endpoint's connection and key go, long before the idle timeout"
        );
        eventually("the removed endpoint's slot to come back", || {
            gone_budget.try_acquire_connection().is_some()
        })
        .await;
        eventually("the upstream to see the proxy close the connection", || {
            gone.closed_by_client() == 1
        })
        .await;

        assert_eq!(alive.closed_by_client(), 0);
        caches
            .round_trip(alive_key, &alive_pool)
            .await
            .expect("the member endpoint's connection is still usable");
        assert_eq!(alive.accepted(), 1, "and was reused, not redialed");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h1_removed_endpoints_idle_connection_is_closed_at_the_next_sweep() {
        LocalSet::new()
            .run_until(
                a_removed_endpoints_idle_connection_is_closed_at_the_next_sweep(
                    UpstreamProtocol::Http1,
                ),
            )
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_removed_endpoints_idle_connection_is_closed_at_the_next_sweep() {
        LocalSet::new()
            .run_until(
                a_removed_endpoints_idle_connection_is_closed_at_the_next_sweep(
                    UpstreamProtocol::Http2,
                ),
            )
            .await;
    }

    /// A stream already running on a removed endpoint's h2 connection is not
    /// cut by the sweep: the connection leaves the cache (nothing new is placed
    /// on it) but keeps its slot until the stream ends, and then closes.
    #[tokio::test(flavor = "current_thread")]
    async fn a_removed_endpoints_h2_stream_in_flight_finishes_before_the_connection_closes() {
        LocalSet::new()
            .run_until(async {
                let host = Upstream::spawn_holding(UpstreamProtocol::Http2, Hold::Body).await;
                let budget = one_connection_budget();
                let caches = Caches::new();
                let removed = Rc::new(std::cell::Cell::new(None));
                install_membership(&caches, &all_but(&removed));
                let key = key_on("up", host.addr, UpstreamProtocol::Http2, &budget);
                let response = caches
                    .h2
                    .get_or_connect(key, &pool_on(host.addr, &budget))
                    .await
                    .expect("dial")
                    .send(get_request())
                    .await
                    .expect("the response head arrives; its body is still streaming");

                removed.set(Some(host.addr));
                assert_eq!(
                    caches.sweep(UpstreamProtocol::Http2, Instant::now()),
                    SweepReport {
                        connections: 1,
                        keys: 1
                    },
                    "the connection leaves the cache so nothing new is placed on it"
                );
                for _ in 0..100 {
                    tokio::task::yield_now().await;
                }
                assert!(
                    budget.try_acquire_connection().is_none(),
                    "the stream on it is not cut, so the connection keeps its slot"
                );

                host.release(1);
                response
                    .body
                    .collect()
                    .await
                    .expect("the stream finishes on the removed endpoint's connection");
                eventually("the finished connection to close and free its slot", || {
                    budget.try_acquire_connection().is_some()
                })
                .await;
            })
            .await;
    }

    /// A refused dial leaves nothing in the map -- checked without the sweep
    /// having run -- and a checkout that was queued behind the failed one still
    /// lands its connection in the map, where the next request finds it.
    #[tokio::test(flavor = "current_thread")]
    async fn a_failed_dial_removes_its_slot_but_not_one_another_checkout_is_waiting_on() {
        LocalSet::new()
            .run_until(async {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let dead_addr = listener.local_addr().unwrap();
                drop(listener);
                let host = Upstream::spawn(UpstreamProtocol::Http2).await;
                let cache = Rc::new(UpstreamConnCache::new());
                let key = test_key("up", host.addr, UpstreamProtocol::Http2);

                cache
                    .get_or_connect(key.clone(), &plaintext_pool(dead_addr))
                    .await
                    .expect_err("nothing is listening");
                assert!(
                    cache.slots.borrow().is_empty(),
                    "the failed dial's empty slot is removed, with no sweep needed"
                );

                // Checkout 1 parks in a dial that will fail; checkout 2 queues
                // on the same key's lock with a pool that works.
                let gate = Arc::new(Notify::new());
                let failing = GatedPool {
                    inner: plaintext_pool(dead_addr),
                    gate: gate.clone(),
                };
                let first = tokio::task::spawn_local({
                    let (cache, key) = (cache.clone(), key.clone());
                    async move { cache.get_or_connect(key, &failing).await.map(|_| ()) }
                });
                settle("checkout 1 to take the key's lock and park", || {
                    cache.slots.borrow().len() == 1
                })
                .await;
                let second = tokio::task::spawn_local({
                    let (cache, key) = (cache.clone(), key.clone());
                    let live = plaintext_pool(host.addr);
                    async move { cache.get_or_connect(key, &live).await }
                });
                settle("checkout 2 to queue on the slot", || {
                    cache.slots.borrow().values().map(Rc::strong_count).max() == Some(3)
                })
                .await;

                gate.notify_one();
                first.await.unwrap().expect_err("checkout 1's dial fails");
                let second = second
                    .await
                    .unwrap()
                    .expect("checkout 2 dials and succeeds");
                assert_eq!(cache.slots.borrow().len(), 1, "checkout 2's slot is kept");

                // The h2 handshake returns before the upstream has accepted
                // the socket, so `accepted()` may still lag a fresh dial. A
                // served request proves its connection was accepted, which
                // makes the count below exact whichever way the third
                // checkout goes.
                second
                    .send(get_request())
                    .await
                    .expect("request on checkout 2");
                let third = cache
                    .get_or_connect(key, &plaintext_pool(host.addr))
                    .await
                    .expect("third checkout");
                third
                    .send(get_request())
                    .await
                    .expect("request on the third checkout");
                assert_eq!(
                    host.accepted(),
                    1,
                    "the third checkout reuses checkout 2's connection; a second one means \
                     checkout 1's cleanup removed the slot checkout 2 was dialing into"
                );
            })
            .await;
    }

    /// The whole production path for idle expiry, timer included: the cache
    /// starts its own sweep task when it dials, the task wakes every
    /// `SWEEP_INTERVAL`, and a connection idle for `UPSTREAM_IDLE_TIMEOUT` is
    /// closed -- slot freed, socket closed -- with nobody calling the sweep.
    ///
    /// Time is frozen only once all socket I/O is done and thawed again before
    /// the last wait. With the clock paused for the whole test, tokio
    /// auto-advances it whenever the runtime waits for I/O, which would race
    /// the connect and the waits' own timeouts.
    async fn an_idle_connection_is_closed_after_the_upstream_idle_timeout(
        protocol: UpstreamProtocol,
    ) {
        let host = Upstream::spawn(protocol).await;
        let budget = one_connection_budget();
        let caches = Caches::new();
        let key = key_on("up", host.addr, protocol, &budget);
        caches
            .round_trip(key, &pool_on(host.addr, &budget))
            .await
            .unwrap();
        assert!(
            budget.try_acquire_connection().is_none(),
            "premise: the idle pooled connection holds the slot"
        );

        tokio::time::pause();
        tokio::time::advance(UPSTREAM_IDLE_TIMEOUT - Duration::from_secs(120)).await;
        assert_eq!(
            caches.sweep(protocol, Instant::now()),
            SweepReport::default(),
            "a connection idle for less than the timeout is kept"
        );

        tokio::time::advance(Duration::from_secs(180)).await;
        settle(
            "the periodic sweep to close the connection that has been idle for an hour",
            || budget.try_acquire_connection().is_some(),
        )
        .await;

        tokio::time::resume();
        eventually("the upstream to see the proxy close the connection", || {
            host.closed_by_client() == 1
        })
        .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h1_idle_connection_is_closed_after_the_upstream_idle_timeout() {
        LocalSet::new()
            .run_until(
                an_idle_connection_is_closed_after_the_upstream_idle_timeout(
                    UpstreamProtocol::Http1,
                ),
            )
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_idle_connection_is_closed_after_the_upstream_idle_timeout() {
        LocalSet::new()
            .run_until(
                an_idle_connection_is_closed_after_the_upstream_idle_timeout(
                    UpstreamProtocol::Http2,
                ),
            )
            .await;
    }

    /// An h2 connection is idle only while it carries no stream. An LLM
    /// response can stream for longer than the idle timeout, and the sweep must
    /// not close a connection out from under it however old the connection
    /// is. And the idle clock starts when the last stream ends, not when the
    /// connection was dialed.
    #[tokio::test(flavor = "current_thread")]
    async fn an_h2_connection_with_a_stream_in_flight_is_not_idle() {
        LocalSet::new()
            .run_until(async {
                // The head goes out at once and the body streams until released.
                let host = Upstream::spawn_holding(UpstreamProtocol::Http2, Hold::Body).await;
                let budget = one_connection_budget();
                let caches = Caches::new();
                let key = key_on("up", host.addr, UpstreamProtocol::Http2, &budget);
                let response = caches
                    .h2
                    .get_or_connect(key, &pool_on(host.addr, &budget))
                    .await
                    .expect("dial")
                    .send(get_request())
                    .await
                    .expect("the response head arrives; its body is still streaming");

                // Two idle timeouts pass while the body streams.
                tokio::time::pause();
                tokio::time::advance(2 * UPSTREAM_IDLE_TIMEOUT).await;
                assert_eq!(
                    caches.sweep(UpstreamProtocol::Http2, Instant::now()),
                    SweepReport::default(),
                    "a connection carrying a stream is not idle, however old it is"
                );
                assert!(
                    budget.try_acquire_connection().is_none(),
                    "the connection is still open and still holds its slot"
                );
                tokio::time::resume();

                host.release(1);
                response
                    .body
                    .collect()
                    .await
                    .expect("the stream finishes on the same connection");

                let just_idle = Instant::now();
                assert_eq!(
                    caches.sweep(UpstreamProtocol::Http2, just_idle),
                    SweepReport::default(),
                    "a connection that has only just gone idle is kept, though it was dialed \
                     two hours ago"
                );
                assert_eq!(
                    caches.sweep(
                        UpstreamProtocol::Http2,
                        just_idle + UPSTREAM_IDLE_TIMEOUT - Duration::from_secs(60)
                    ),
                    SweepReport::default()
                );
                assert_eq!(
                    caches.sweep(
                        UpstreamProtocol::Http2,
                        just_idle + UPSTREAM_IDLE_TIMEOUT + Duration::from_secs(60)
                    ),
                    SweepReport {
                        connections: 1,
                        keys: 1
                    },
                    "an hour after its last stream ended, the connection is idle and goes"
                );
            })
            .await;
    }

    /// Evicting a cache entry is not closing its connection. When an h2 entry
    /// is dropped (`invalidate`, after a send error) while a response is still
    /// streaming, hyper keeps the socket open until that stream ends -- and the
    /// connection's slot must stay held until then, because the connection is
    /// still using it. Then, with nobody left holding the connection, it closes
    /// and the slot comes back.
    #[tokio::test(flavor = "current_thread")]
    async fn evicting_an_h2_connection_keeps_its_slot_until_the_stream_on_it_ends() {
        LocalSet::new()
            .run_until(async {
                let host = Upstream::spawn_holding(UpstreamProtocol::Http2, Hold::Body).await;
                let budget = one_connection_budget();
                let caches = Caches::new();
                let key = key_on("up", host.addr, UpstreamProtocol::Http2, &budget);
                let response = caches
                    .h2
                    .get_or_connect(key.clone(), &pool_on(host.addr, &budget))
                    .await
                    .expect("dial")
                    .send(get_request())
                    .await
                    .expect("the response head arrives; its body is still streaming");

                // The cache lets go of the connection. No `SendRequest` handle
                // is left anywhere: only the streaming body still uses it.
                caches.h2.invalidate(&key);
                for _ in 0..100 {
                    tokio::task::yield_now().await;
                }
                assert!(
                    budget.try_acquire_connection().is_none(),
                    "the evicted connection is still carrying a stream, so it still holds its slot"
                );

                host.release(1);
                response
                    .body
                    .collect()
                    .await
                    .expect("the stream survives its connection being evicted from the cache");
                eventually("the finished, unreferenced connection to close", || {
                    budget.try_acquire_connection().is_some()
                })
                .await;
            })
            .await;
    }

    /// The sweep must not take a key out of the map from under a checkout that
    /// is dialing it: the connection that checkout produces would be stored in
    /// a slot nothing can reach, and the next request would dial again.
    #[tokio::test(flavor = "current_thread")]
    async fn the_sweep_does_not_retire_a_key_a_checkout_is_dialing() {
        LocalSet::new()
            .run_until(async {
                let host = Upstream::spawn(UpstreamProtocol::Http2).await;
                let gate = Arc::new(Notify::new());
                let gated = GatedPool {
                    inner: plaintext_pool(host.addr),
                    gate: gate.clone(),
                };
                let caches = Caches::new();
                let key = test_key("up", host.addr, UpstreamProtocol::Http2);

                // A checkout parked in the middle of its dial, holding the key.
                let dialing = tokio::task::spawn_local({
                    let (h2, key) = (caches.h2.clone(), key.clone());
                    async move { h2.get_or_connect(key, &gated).await }
                });
                settle("the checkout to register its key and park", || {
                    caches.h2.slots.borrow().len() == 1
                })
                .await;

                assert_eq!(
                    caches.sweep(UpstreamProtocol::Http2, Instant::now()),
                    SweepReport::default(),
                    "a key with a checkout in flight is not empty-and-unused"
                );

                gate.notify_one();
                let leased = dialing.await.unwrap().expect("the dial completes");
                leased.send(get_request()).await.unwrap();
                caches
                    .round_trip(key, &plaintext_pool(host.addr))
                    .await
                    .unwrap();
                assert_eq!(
                    host.accepted(),
                    1,
                    "the second checkout reuses the connection the first dialed; a second \
                     connection means the first landed in a slot the sweep had already retired"
                );
            })
            .await;
    }
}
