//! HTTP filter API matching Envoy iteration semantics (S2). This shared surface
//! is frozen by AGENTS.md invariant 8.
//!
//! Rust note: we model Envoy's C++ virtual-method filter classes as *traits*
//! (Rust's interfaces). A filter instance is held as `Box<dyn HttpFilter>` — a
//! "trait object": a pointer to some concrete type plus a vtable, dispatched at
//! runtime like a C++ virtual call. We use trait objects (not generics) because
//! the set of filters on a stream is decided by config at runtime.

use std::any::Any;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use bytes::{Bytes, BytesMut};
use http::{HeaderMap, Method, StatusCode, Uri};
use proxy_config::ir::RouteEntry;
use proxy_config::ConfigError;
use tokio::sync::Notify;

use crate::handler::HttpResponseParts;
use crate::stream_info::StreamInfo;

/// Request head. Pseudo-header data (`:method`, `:path`, `:authority`) is carried
/// in the typed fields; `headers` holds regular headers only.
#[derive(Debug, Clone)]
pub struct RequestHeaders {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
}

#[derive(Debug)]
pub struct ResponseHeaders {
    pub status: StatusCode,
    pub headers: HeaderMap,
}

/// Rust note: a "newtype" — a one-field tuple struct wrapping `HeaderMap` so the
/// type system distinguishes request trailers from plain header maps.
#[derive(Debug, Default)]
pub struct RequestTrailers(pub HeaderMap);

#[derive(Debug, Default)]
pub struct ResponseTrailers(pub HeaderMap);

/// S2.2 — statuses a filter may return from `decode_headers` / `encode_headers`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FilterHeadersStatus {
    #[default]
    Continue,
    /// Headers held. NOTE (S2.2 gotcha): data callbacks for this filter still
    /// fire while stopped — data is NOT implicitly buffered.
    StopIteration,
    /// Forward headers with `end_stream=false` even if the message had no body;
    /// the filter must later inject data ending the stream (S2.2).
    ContinueAndDontEndStream,
    /// Nothing (headers/data/trailers) proceeds past this filter; incoming data
    /// is buffered; buffer overflow => 413 (decode) / 500 (encode).
    StopAllIterationAndBuffer,
    /// As above, but overflow applies backpressure (watermarks) instead of erroring.
    StopAllIterationAndWatermark,
}

/// S2.3 — statuses from `decode_data` / `encode_data`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FilterDataStatus {
    /// Proceed; if headers are still held (plain `StopIteration`) they are sent first.
    #[default]
    Continue,
    /// Buffer this chunk in the filter-manager buffer; overflow => 413/500.
    StopIterationAndBuffer,
    /// Buffer; overflow applies backpressure (watermarks).
    StopIterationAndWatermark,
    /// Stop without accumulating; resumption still requires `continue_*()`.
    StopIterationNoBuffer,
}

/// S2.4 — statuses from trailer callbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FilterTrailersStatus {
    #[default]
    Continue,
    StopIteration,
}

/// S2.6 — statuses from `encode_1xx_headers`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Filter1xxStatus {
    #[default]
    Continue,
    StopIteration,
}

/// Body bytes buffered by the filter manager for one direction of one stream.
#[derive(Debug, Default)]
pub struct BufferedBody(pub BytesMut);

/// Rust note: a boxed closure. `FnOnce` = callable exactly once; `Send` lets it
/// cross threads. Used to let `send_local_reply` callers mutate response headers.
pub type HeaderMutationFn = Box<dyn FnOnce(&mut HeaderMap) + Send>;

/// Cloneable handle for resuming a decode `StopAll*` hold outside callback
/// context, when work completes independently of `poll_pending`.
///
/// Rust note: worker-local `Rc` keeps this handle `!Send` (ADR-0003).
/// `Notify` stores an early permit, so resuming before the driver parks cannot
/// lose the wakeup.
#[derive(Clone)]
pub struct DecodeContinueHandle {
    resume: Rc<Notify>,
}

impl DecodeContinueHandle {
    /// Built by whoever owns the real per-stream signal — the adapter
    /// (`filter_manager::DecoderCallbacksAdapter::continue_handle`) wires
    /// this to the direction's actual resume `Notify`; [`DecoderCallbacks::continue_handle`]'s
    /// default builds a throwaway one instead (see that method's doc).
    pub(crate) fn new(resume: Rc<Notify>) -> Self {
        Self { resume }
    }

    /// Resume a stalled decode-direction `StopAll*` hold. Safe to call any
    /// number of times, and safe to call before the driver has actually
    /// parked on it (see the struct doc's `Notify` note) — a call that
    /// "arrives early" is remembered, not dropped.
    pub fn continue_decoding(&self) {
        self.resume.notify_one();
    }
}

/// Callbacks available to decoder (request-path) filters — S2.5 / S2.7 / S2.8.
///
/// Rust note: filters receive `&mut dyn DecoderCallbacks` — a mutable borrow of a
/// trait object owned by the filter manager. The borrow checker guarantees a
/// filter can't stash this reference and use it after the stream is gone (that
/// class of use-after-free is an actual recurring Envoy CVE pattern).
pub trait DecoderCallbacks {
    /// S2.5: local reply. Before response headers have been forwarded this
    /// synthesizes a response through the ENCODER chain; after, it resets the stream.
    fn send_local_reply(
        &mut self,
        code: StatusCode,
        body: &str,
        modify_headers: Option<HeaderMutationFn>,
        details: &str,
    );

    /// Send a protocol-provided body verbatim, without text formatting.
    fn send_local_reply_exact(
        &mut self,
        code: StatusCode,
        body: &str,
        modify_headers: Option<HeaderMutationFn>,
        details: &str,
    ) {
        self.send_local_reply(code, body, modify_headers, details);
    }

    /// Resume iteration at the NEXT filter, replaying buffered body then trailers.
    fn continue_decoding(&mut self);

    /// A cloneable handle that can call the equivalent of
    /// [`Self::continue_decoding`] from OUTSIDE callback context — see [`DecodeContinueHandle`]'s doc for the whole
    /// out-of-band-continue story.
    ///
    /// Rust note: defaulted (like [`Self::modify_decoded_headers`] and
    /// [`EncoderCallbacks::per_route_config`]) so existing test-double
    /// implementors of this trait outside the filter manager keep
    /// compiling — the default builds a handle over its OWN throwaway
    /// `Notify` that nothing ever awaits, so calling `continue_decoding()`
    /// on it is a harmless no-op rather than a compile break. The real
    /// adapter (`filter_manager::DecoderCallbacksAdapter`) overrides this
    /// with a handle wired to the direction's actual resume signal.
    fn continue_handle(&mut self) -> DecodeContinueHandle {
        DecodeContinueHandle::new(Rc::new(Notify::new()))
    }

    /// Append to the buffered body (legal from headers/data/trailers callbacks).
    fn add_decoded_data(&mut self, data: Bytes, streaming: bool);

    /// Deliver data directly to subsequent filters, outside callback context
    /// (pairs with `ContinueAndDontEndStream`).
    fn inject_decoded_data_to_filter_chain(&mut self, data: Bytes, end_stream: bool);

    fn decoding_buffer(&self) -> Option<&BufferedBody>;

    /// Only legal before any data has been continued past this filter (S2.7).
    fn modify_decoding_buffer(&mut self, f: &mut dyn FnMut(&mut BytesMut));

    /// Mutate request headers that have not yet been forwarded upstream
    /// (the seam a decode filter needs to fix up
    /// `content-length` after splicing bytes into the body, since that's a
    /// case `modify_decoding_buffer` alone can't cover).
    ///
    /// Applies `f` through a genuine live `&mut RequestHeaders` borrow of the
    /// real request head — no clone, no splice-back, so it can never
    /// silently discard a mutation a filter made some other way.
    ///
    /// Returns `false` and does nothing if the headers have already been
    /// sent, so a late caller is a no-op rather than a silent lie. It ALSO
    /// returns `false` and does nothing when called from **`decode_headers`
    /// itself**: `decode_headers` already hands the
    /// filter a direct `&mut RequestHeaders` parameter that IS the request
    /// head, and Rust's aliasing rules mean this callback cannot also hold a
    /// second live `&mut` to that same value while the filter is still
    /// holding the first one — there is no clone-free way to give both
    /// access at once, and a clone-based workaround is exactly what
    /// reintroduced a data-loss bug (a stale pre-callback clone spliced back over a direct mutation; see
    /// `filter_manager::tests::probe_direct_and_seam_mutations_coexist`). A
    /// filter running in `decode_headers` should mutate its `headers`
    /// parameter directly instead — it needs no seam there. `decode_data`
    /// and `decode_trailers` (the real use case: the decision to splice
    /// body bytes, and so the need to fix up `content-length`, is only made
    /// once body bytes have been scanned) have no such parameter and DO get
    /// the real working borrow.
    ///
    /// Mutating routing-relevant headers (`:authority`, `:path`) through this
    /// does NOT auto-invalidate the S2.8 route cache, same as everywhere
    /// else a filter can reach the request head — call
    /// [`Self::clear_route_cache`] afterward if the rewrite should affect
    /// routing.
    ///
    /// Rust note: defaulted to a no-op returning `false` (unlike most of this
    /// trait, and like [`EncoderCallbacks::per_route_config`]'s default) —
    /// `DecoderCallbacks` already has test-double implementors outside the
    /// filter manager that this change must not force edits onto; the
    /// real adapter (`filter_manager::DecoderCallbacksAdapter`) overrides
    /// this with the actual mutation.
    fn modify_decoded_headers(&mut self, _f: &mut dyn FnMut(&mut RequestHeaders)) -> bool {
        false
    }

    /// The cached route (S2.8). Resolved lazily on first access: the manager
    /// matches against the LIVE `:authority`/`:path` (as of whichever filter
    /// callback is running) the first time this is called, caches the result,
    /// and returns the cached `Arc` on every subsequent call until
    /// `clear_route_cache()` drops it. `&mut self` (not `&self`): resolving is
    /// the whole point, and that has to write the cache.
    fn route(&mut self) -> Option<Arc<RouteEntry>>;

    /// S2.8: the route cache is NOT auto-invalidated — any filter mutating
    /// routing-relevant headers must call this (differential fixture required).
    fn clear_route_cache(&mut self);

    /// The most specific `typed_per_filter_config` entry that applies to the
    /// CALLING filter for this stream's route, or `None` (ADR-0004).
    ///
    /// Specificity, most to least (Envoy's `mostSpecificPerFilterConfig`):
    /// route > virtual host > route configuration. Resolving this resolves
    /// the route (S2.8), so it is subject to the same cache and the same
    /// `clear_route_cache()` invalidation — a filter that rewrites
    /// routing-relevant headers and wants the rewritten route's override
    /// must call `clear_route_cache()` first, exactly as for [`Self::route`]
    /// itself.
    ///
    /// A filter only ever sees ITS OWN entry: the filter manager resolves
    /// this against the position of whichever filter is calling right now
    /// (never another filter's position), so one filter can't read another
    /// filter's per-route config.
    fn per_route_config(&mut self) -> Option<Arc<dyn PerRouteConfig>>;

    /// The stream's single [`StreamInfo`] (Envoy's model: one per stream,
    /// owned at the filter-manager level, written by every filter AND by the
    /// router terminal — see `filter_manager::FilterChainHandler::handle`).
    ///
    /// Rust note: `RefMut<'_, T>` implements `DerefMut`, so both
    /// `cb.stream_info().field = x` and
    /// `let mut si = cb.stream_info(); si.a = 1; si.b = 2;` still compile
    /// unchanged — this is a much smaller change at call sites than the
    /// signature suggests. The guard MUST NOT be held across another call on
    /// this same callbacks object (e.g. `cb.route()`, `cb.continue_decoding()`)
    /// or the underlying `RefCell` panics at runtime — drop it (end the
    /// statement/block) before making another call.
    fn stream_info(&mut self) -> std::cell::RefMut<'_, StreamInfo>;

    /// The most request body bytes this stream may buffer: the listener's
    /// `per_connection_buffer_limit_bytes` (Envoy's `decoderBufferLimit()`).
    /// The router uses it as the retry replay limit (S3.4), so raising the
    /// listener limit also raises the largest retriable body, as in Envoy.
    ///
    /// Rust note: defaulted, like [`Self::modify_decoded_headers`], so test
    /// doubles outside the filter manager need no edit; the real adapter
    /// returns the stream's actual limit.
    fn decoder_buffer_limit(&self) -> usize {
        crate::filter_manager::DEFAULT_BUFFER_LIMIT
    }
}

/// Callbacks available to encoder (response-path) filters.
pub trait EncoderCallbacks {
    fn continue_encoding(&mut self);
    fn add_encoded_data(&mut self, data: Bytes, streaming: bool);
    fn inject_encoded_data_to_filter_chain(&mut self, data: Bytes, end_stream: bool);
    fn encoding_buffer(&self) -> Option<&BufferedBody>;
    fn modify_encoding_buffer(&mut self, f: &mut dyn FnMut(&mut BytesMut));

    /// Encoder-side counterpart to [`DecoderCallbacks::per_route_config`] —
    /// same specificity order, same route cache, same per-filter isolation;
    /// see that method's doc.
    ///
    /// Rust note: defaulted to `None` (unlike every other method here, and
    /// unlike [`DecoderCallbacks::per_route_config`], which has no default) —
    /// `EncoderCallbacks` already has test-double implementors outside the
    /// filter manager (`proxy-filters`, `proxy-core`) that this change
    /// must not force edits onto; the real adapter
    /// (`filter_manager::EncoderCallbacksAdapter`) overrides this with the
    /// actual resolution.
    fn per_route_config(&mut self) -> Option<Arc<dyn PerRouteConfig>> {
        None
    }

    /// The stream's single [`StreamInfo`] — see [`DecoderCallbacks::stream_info`]
    /// for the shared-ownership model and the same "don't hold the guard
    /// across another call" rule.
    fn stream_info(&mut self) -> std::cell::RefMut<'_, StreamInfo>;
}

/// A per-stream HTTP filter instance. Decoder callbacks run in config order,
/// encoder callbacks in REVERSE config order (S2.1). Instances are created per
/// stream and destroyed in reverse creation order.
///
/// Rust note: every method has a default body returning `Continue`, so a filter
/// implements only the callbacks it cares about — the Rust equivalent of Envoy's
/// `PassThroughFilter` base class. Parameters in defaults are `_`-prefixed to
/// tell the compiler "unused on purpose".
///
/// Rust note: intentionally NOT `Send` (ADR-0003). A filter instance is created
/// per stream and lives entirely on one worker's `!Send` runtime, so it may hold
/// `Rc`/`RefCell` and share worker-local state freely; it never crosses threads.
/// Only the config-time plumbing that DOES cross threads — [`FilterInstanceFactory`],
/// [`HttpFilterFactory`], [`PerRouteConfig`] — carries `Send + Sync`.
pub trait HttpFilter {
    /// Body-independent admission prefix, executed before polling downstream data.
    fn decode_before_body(&self) -> bool {
        false
    }
    fn decode_headers(
        &mut self,
        _cb: &mut dyn DecoderCallbacks,
        _headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        FilterHeadersStatus::Continue
    }

    fn decode_data(
        &mut self,
        _cb: &mut dyn DecoderCallbacks,
        _data: &mut Bytes,
        _end_stream: bool,
    ) -> FilterDataStatus {
        FilterDataStatus::Continue
    }

    fn decode_trailers(
        &mut self,
        _cb: &mut dyn DecoderCallbacks,
        _trailers: &mut RequestTrailers,
    ) -> FilterTrailersStatus {
        FilterTrailersStatus::Continue
    }

    fn encode_headers(
        &mut self,
        _cb: &mut dyn EncoderCallbacks,
        _headers: &mut ResponseHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        FilterHeadersStatus::Continue
    }

    fn encode_data(
        &mut self,
        _cb: &mut dyn EncoderCallbacks,
        _data: &mut Bytes,
        _end_stream: bool,
    ) -> FilterDataStatus {
        FilterDataStatus::Continue
    }

    fn encode_trailers(
        &mut self,
        _cb: &mut dyn EncoderCallbacks,
        _trailers: &mut ResponseTrailers,
    ) -> FilterTrailersStatus {
        FilterTrailersStatus::Continue
    }

    fn encode_1xx_headers(
        &mut self,
        _cb: &mut dyn EncoderCallbacks,
        _headers: &mut ResponseHeaders,
    ) -> Filter1xxStatus {
        Filter1xxStatus::Continue
    }

    /// Called exactly once per filter when the response stream is over, before
    /// the access log reads `StreamInfo` and before [`Self::on_destroy`]
    /// (Envoy's `onStreamComplete`). It runs for a clean end, a local reply,
    /// and a stream abandoned part-way (client disconnect), in reverse
    /// creation order. Unlike `on_destroy` it has callbacks, so a filter that
    /// writes its observations to `StreamInfo` at stream end can still do so
    /// for a stream that never delivered its terminal frame.
    ///
    /// Only [`EncoderCallbacks::stream_info`] is meaningful here; the buffer
    /// and continuation methods have nothing left to act on, and a response
    /// that failed before any encode phase ran may not have per-route config.
    fn on_stream_complete(&mut self, _cb: &mut dyn EncoderCallbacks) {}

    /// Called once when the stream ends or resets; release resources here.
    fn on_destroy(&mut self) {}

    /// Asynchronous continuation, polled by the filter manager after this
    /// filter has returned a `StopIteration*` status from a decode callback.
    ///
    /// `Some(fut)` means "I have work in flight: await it, then re-drive the
    /// chain from me". `None` — the default — keeps the existing meaning:
    /// stopped until something calls `continue_decoding()`.
    ///
    /// Anything the filter needs from its callbacks must be captured BEFORE
    /// returning the future: the future borrows only `self`, not the
    /// callbacks. Results are applied on the next synchronous callback, when
    /// callbacks are available again. See ADR-0004 for why.
    ///
    /// Rust note: a boxed, pinned, `!Send` future — the same shape
    /// `StreamHandler` already uses (`crate::handler`), and for the same
    /// reason: an `async fn` in a trait isn't object-safe (its `Future` type
    /// would have to be part of the trait's vtable, which Rust doesn't
    /// support), so we return the desugared form by hand. `!Send` is correct
    /// per ADR-0003 — the whole stream, filters included, lives on one
    /// worker's `!Send` `LocalSet`, so nothing here ever needs to cross a
    /// thread. The `'a` lifetime ties the future to the `&mut self` borrow
    /// that produced it: the borrow checker then guarantees the future can't
    /// outlive (or be polled after) the filter instance it reads from.
    fn poll_pending<'a>(
        &'a mut self,
    ) -> Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>>> {
        None
    }
}

/// ADR-0004 step 3: the terminal filter — Envoy's `Router::Filter`. An
/// ordinary [`HttpFilter`] for the decode direction (it lives at the LAST
/// position of the decode chain, created and destroyed exactly like any other
/// filter instance); once the decode chain reaches it with the complete
/// request, `respond` produces the response, which the filter manager then
/// drives into the ENCODE chain — exactly the position Envoy's `Router::Filter`
/// occupies.
///
/// Rust note: same boxed/pinned/`!Send` future shape as
/// [`HttpFilter::poll_pending`], and for the same reason (object safety —
/// `async fn` in a trait can't be called through a trait object). The `'a`
/// lifetime ties the future to both the `&mut self` and `&mut dyn
/// DecoderCallbacks` borrows that produced it.
pub trait TerminalHttpFilter: HttpFilter {
    fn respond<'a>(
        &'a mut self,
        cb: &'a mut dyn DecoderCallbacks,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HttpResponseParts> + 'a>>;
}

/// Created once per (filter config, listener); creates the per-stream
/// terminal instance — the [`TerminalHttpFilter`] counterpart to
/// [`FilterInstanceFactory`].
///
/// `Send + Sync`, exactly like `FilterInstanceFactory` — per ADR-0003,
/// config-time plumbing (built once from config and shared by every worker)
/// crosses threads and carries `Send + Sync`; only the per-stream instances
/// it mints ([`TerminalHttpFilter`]) are deliberately `!Send` (see
/// [`HttpFilter`]'s doc). Holders of a `dyn TerminalFilterInstanceFactory`
/// use `Arc`, same as `FilterInstanceFactory`.
pub trait TerminalFilterInstanceFactory: Send + Sync {
    fn create_terminal_filter(&self) -> Box<dyn TerminalHttpFilter>;
}

/// Marker trait for parsed per-route filter config (`typed_per_filter_config`).
pub trait PerRouteConfig: Send + Sync {
    fn merge_from(&self, _less_specific: &dyn PerRouteConfig) -> Option<Arc<dyn PerRouteConfig>> {
        None
    }
    /// Rust note: trait objects have no built-in way to recover their
    /// concrete type; `dyn PerRouteConfig` alone can't be downcast. Each
    /// implementor forwards this to `self` (`fn as_any(&self) -> &dyn Any {
    /// self }`) so a filter that receives `Arc<dyn PerRouteConfig>` from
    /// `per_route_config()` can `downcast_ref::<ItsOwnConcreteType>()` it
    /// back — the only way it reads what its own `parse_per_route`
    /// produced.
    fn as_any(&self) -> &dyn std::any::Any;
}

/// Config-time singletons shared across the per-worker filter-factory
/// invocations of ONE serve. The HTTP filter chain is rebuilt per worker
/// (ADR-0003), so a factory that must expose ONE process-wide instance
/// (e.g. a control plane owning a mutable store) registers it here keyed by
/// its own `type_url`; every later per-worker `create` for that filter reads
/// the same instance back, and the control side can read it out too.
///
/// proxy-http intentionally knows nothing about what these singletons ARE —
/// naming a concrete filter type here would invert the crate dependency
/// (proxy-filters depends on proxy-http, not the reverse). They are
/// `dyn Any + Send + Sync`, downcast by the crate that owns the concrete type.
///
/// The map key is `(scope, type_url)`, not `type_url` alone. `build_hcm_handler`
/// (`proxy-core`) runs once PER FILTER CHAIN, and every chain in a serve is
/// handed the same `Arc<SharedFactoryState>` — so `type_url` alone would let
/// two listeners (or two chains on one listener) that both configure the same
/// filter collide: the first chain to build wins the slot, and the second
/// chain's own parsed config is silently discarded in favor of the first's
/// (found on the auth path — AGENTS.md invariant 1). `scope` is the chain identity
/// (`FactoryContext::scope`, set from `build_hcm_handler`'s own `context`
/// parameter); every filter built for one chain shares one scope, so
/// cross-filter reads within a chain (e.g. `model_authz` reading `auth`'s
/// `ControlPlane`) still see the same instance.
///
/// Rust note: `type_url` stays `&'static str` (every caller passes a literal
/// constant); only `scope` needs to be an owned `String` — it is built per
/// chain build (`format!(...)` in `build_hcm_handler`'s caller), so nothing
/// `'static` is available to borrow.
///
/// A second map, `by_name`, indexes the SAME `Arc`s by
/// `(stat_prefix, type_url)` — see [`FactoryContext`]'s doc for why `scope`
/// and `stat_prefix` are two different identities, not one renamed. Both
/// maps are populated together in `get_or_try_init`; nothing is ever in one
/// and not the other.
#[derive(Default)]
pub struct SharedFactoryState {
    singletons: Mutex<HashMap<SingletonKey, Arc<dyn Any + Send + Sync>>>,
    by_name: Mutex<HashMap<SingletonKey, Arc<dyn Any + Send + Sync>>>,
    /// The effective node id of this process (ADR-0006 §2): the
    /// `--service-node` CLI override if given, else the bootstrap's
    /// `node.id`. An empty string means no node identity was configured --
    /// via `#[derive(Default)]`, every test `SharedFactoryState::default()`
    /// gets one. It is NOT this type's job to reject that; a consuming
    /// filter (e.g. the spend flush token, which needs a node id to
    /// disambiguate its counter across replicas) decides for itself whether
    /// an empty id is fatal to its own purpose.
    node_id: String,
}

/// `SharedFactoryState`'s map key -- pulled out to a named type purely to
/// satisfy clippy's `type_complexity` lint on the `HashMap` above; it carries
/// no behavior of its own. Used for both the `scope`-keyed and
/// `stat_prefix`-keyed maps -- both keys are `(String, &'static str)` shaped.
type SingletonKey = (String, &'static str);

impl SharedFactoryState {
    /// Production constructor: build state for one serve carrying `node_id`
    /// as this process's effective node identity. `main.rs` computes
    /// `node_id` once (`effective_node`) and calls this instead of
    /// `::default()`; tests that have no need of a node identity keep using
    /// `::default()`, which leaves it `""`.
    pub fn for_node(node_id: String) -> Self {
        Self {
            node_id,
            ..Default::default()
        }
    }

    /// This process's effective node id (ADR-0006 §2), or `""` if none was
    /// configured -- see the field's own doc for why an empty value is not
    /// rejected here.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Return the singleton under `(scope, type_url)`, building and inserting
    /// it via `init` on the first call for that key. Concurrent first-callers
    /// (workers build their chains on separate runtimes) serialize on the
    /// lock; exactly one runs `init`, the rest receive its result. `init`
    /// MUST NOT call back into this method (it runs while the lock is held).
    ///
    /// `stat_prefix` is the chain's external name (see [`FactoryContext`]'s
    /// doc): on the first build for this `scope`, the same `Arc` is also
    /// recorded under `(stat_prefix, type_url)` so [`Self::get_by_name`] can
    /// find it later. A `scope` that already has a singleton for this
    /// `type_url` returns the existing `Arc` without touching `by_name` again
    /// -- the name index is populated once, at the same moment the scope
    /// index is.
    pub fn get_or_try_init(
        &self,
        scope: &str,
        stat_prefix: &str,
        type_url: &'static str,
        init: impl FnOnce() -> Result<Arc<dyn Any + Send + Sync>, ConfigError>,
    ) -> Result<Arc<dyn Any + Send + Sync>, ConfigError> {
        let mut guard = self
            .singletons
            .lock()
            .expect("SharedFactoryState mutex poisoned");
        // Rust note: `HashMap::get` needs a borrowed key matching the stored
        // key's shape — `(&str, &'static str)` doesn't satisfy `Borrow<(String,
        // &'static str)>`, so the lookup key is built as an owned tuple. Cheap
        // (one allocation) and only on the cold path relative to holding the
        // lock at all.
        let key = (scope.to_string(), type_url);
        if let Some(existing) = guard.get(&key) {
            return Ok(Arc::clone(existing));
        }
        let built = init()?;
        guard.insert(key, Arc::clone(&built));
        // Populate the name index under the same lock ordering discipline
        // (singletons first, then by_name) every call site uses -- there is
        // only this one call site, so no ordering hazard exists yet, but the
        // comment is here for whoever adds a second.
        self.by_name
            .lock()
            .expect("SharedFactoryState mutex poisoned")
            .insert((stat_prefix.to_string(), type_url), Arc::clone(&built));
        Ok(built)
    }

    /// Read a previously-initialized singleton under `(scope, type_url)`
    /// without building one — used by a chain's own later filters (e.g.
    /// `model_authz` reading `auth`'s `ControlPlane`) to reach an instance an
    /// earlier filter in the SAME chain built. `None` until the first
    /// `get_or_try_init` for that exact `(scope, type_url)`.
    pub fn get(&self, scope: &str, type_url: &'static str) -> Option<Arc<dyn Any + Send + Sync>> {
        self.singletons
            .lock()
            .expect("SharedFactoryState mutex poisoned")
            .get(&(scope.to_string(), type_url))
            .map(Arc::clone)
    }

    /// Read a previously-initialized singleton under `(stat_prefix, type_url)`
    /// -- the admin server's scoped lookup (`/chains/{stat_prefix}/...`).
    /// Unlike `scope`, `stat_prefix` is an operator-chosen name (`ir.rs:283`),
    /// so this is safe to expose in a URL or use as a persisted-row key; see
    /// [`FactoryContext`]'s doc for the split. `None` if no chain named
    /// `stat_prefix` has registered a singleton for `type_url` -- ambiguity
    /// cannot happen here the way it can for `get_across_scopes`, because
    /// `proxy-config`'s lowering rejects a duplicate `stat_prefix`
    /// among chains that register an admin-addressable singleton, so at most
    /// one chain can ever occupy this key.
    pub fn get_by_name(
        &self,
        stat_prefix: &str,
        type_url: &'static str,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        self.by_name
            .lock()
            .expect("SharedFactoryState mutex poisoned")
            .get(&(stat_prefix.to_string(), type_url))
            .map(Arc::clone)
    }

    /// Read a singleton by `type_url` alone, across every scope — for
    /// control-plane code (the admin server) that has no chain identity of
    /// its own to scope by. Distinguishes three cases the admin server needs
    /// told apart, rather than guessing:
    /// - `Ok(None)` — no scope has registered `type_url` yet (a boot race, or
    ///   this filter isn't configured anywhere).
    /// - `Ok(Some(_))` — exactly one scope has; unambiguous, so this is the
    ///   one instance the caller means.
    /// - `Err(scopes)` — MORE THAN ONE scope has registered a singleton under
    ///   this `type_url` (e.g. two listeners each configuring `llmproxy.auth`
    ///   with different keys). Returning an arbitrary one here would let an
    ///   admin write land in the wrong tenant's control plane (AGENTS.md
    ///   invariant 1); `scopes` names every chain identity that registered one so the
    ///   caller can say so instead of guessing.
    pub fn get_across_scopes(
        &self,
        type_url: &'static str,
    ) -> Result<Option<Arc<dyn Any + Send + Sync>>, Vec<String>> {
        let guard = self
            .singletons
            .lock()
            .expect("SharedFactoryState mutex poisoned");
        let mut matches = guard
            .iter()
            .filter(|((_, t), _)| *t == type_url)
            .map(|((scope, _), value)| (scope.clone(), Arc::clone(value)));
        let Some((first_scope, first_value)) = matches.next() else {
            return Ok(None);
        };
        match matches.next() {
            None => Ok(Some(first_value)),
            Some((second_scope, _)) => {
                let mut scopes = vec![first_scope, second_scope];
                scopes.extend(matches.map(|(scope, _)| scope));
                scopes.sort();
                Err(scopes)
            }
        }
    }
}

/// Context handed to factories at config time. Carries the per-serve shared
/// singleton slot ([`SharedFactoryState`]) plus this build's TWO chain
/// identities; a stateless filter ignores all three.
///
/// These are two fields with two different jobs (addressing follows Envoy:
/// positional internals vs. an operator-supplied name):
/// - **`scope`** KEYS singletons. It is positional, internal, and always
///   unique per chain build, even for two chains that would otherwise be
///   indistinguishable (same listener config repeated, same `stat_prefix`).
///   Nothing durable or user-facing may be keyed by it — reordering filter
///   chains changes it silently.
/// - **`stat_prefix`** NAMES a chain externally. It is the HCM's
///   operator-supplied `stat_prefix` (`ir.rs:283`), already required and
///   already rendered in `/config_dump`. It is what admin URLs
///   (`/chains/{stat_prefix}/...`) and persisted rows key by,
///   because it is stable under reordering and human-chosen -- but it is
///   only enforced unique among chains that register an admin-addressable
///   singleton (`proxy-config`'s lowering check), so a filter that never calls
///   `get_by_name` must never assume it is unique.
///
/// A reader adding a new call site: singleton lifetime and cross-filter reads
/// within one chain use `scope` (via `get`/`get_or_try_init`); anything
/// exposed outside the process (an admin endpoint, a spend row) uses
/// `stat_prefix` (via `get_by_name`).
/// TODO: stats scope, runtime.
#[derive(Default)]
pub struct FactoryContext {
    pub shared: Arc<SharedFactoryState>,
    /// This filter chain's identity, for [`SharedFactoryState`]'s key —
    /// `build_hcm_handler` (`proxy-core`) sets this from its own `context`
    /// parameter (the same string its error messages use), once per chain
    /// build, shared by every filter factory `create`d for that chain. The
    /// default (`String::new()`, via `#[derive(Default)]`) is the empty scope
    /// every test `FactoryContext::default()` gets — fine there, since a
    /// test only ever builds one chain per `FactoryContext`.
    pub scope: String,
    /// This filter chain's OPERATOR-CHOSEN external name -- the HCM's
    /// `stat_prefix` (`ir.rs:283`), set by `build_hcm_handler` from the same
    /// `HttpConnectionManagerConfig` it already has in hand. See this type's
    /// own doc for why this is a second field, not a rename of `scope`. The
    /// default (`String::new()`) matches `scope`'s: fine for a test that
    /// never calls `get_by_name`.
    pub stat_prefix: String,
}

impl FactoryContext {
    /// Thin wrapper over [`SharedFactoryState::get_or_try_init`] that
    /// supplies this context's own `scope` and `stat_prefix` — the ergonomic
    /// form every filter factory's `create` should call instead of reaching
    /// through `.shared` directly.
    pub fn get_or_try_init(
        &self,
        type_url: &'static str,
        init: impl FnOnce() -> Result<Arc<dyn Any + Send + Sync>, ConfigError>,
    ) -> Result<Arc<dyn Any + Send + Sync>, ConfigError> {
        self.shared
            .get_or_try_init(&self.scope, &self.stat_prefix, type_url, init)
    }

    /// Thin wrapper over [`SharedFactoryState::get`] that supplies this
    /// context's own `scope`.
    pub fn get(&self, type_url: &'static str) -> Option<Arc<dyn Any + Send + Sync>> {
        self.shared.get(&self.scope, type_url)
    }

    /// Thin wrapper over [`SharedFactoryState::node_id`] -- the ergonomic
    /// form a filter factory calls (e.g. spend-flush tokens, ADR-0006 §2)
    /// instead of reaching through `.shared` directly, same pattern as
    /// [`Self::get_or_try_init`].
    pub fn node_id(&self) -> &str {
        self.shared.node_id()
    }
}

/// Created once per (filter config, listener); creates per-stream instances.
pub trait FilterInstanceFactory: Send + Sync {
    fn create_filter(&self) -> Box<dyn HttpFilter>;
}

/// One registered filter implementation, keyed by its Envoy extension type URL
/// (e.g. `type.googleapis.com/envoy.extensions.filters.http.router.v3.Router`).
/// LLM extensions register under `type.llmproxy.dev/...`.
pub trait HttpFilterFactory: Send + Sync {
    fn parse_ext_authz_per_route(
        &self,
        _config: &proxy_config::authorization::ExtAuthzPerRoute,
    ) -> Result<Arc<dyn PerRouteConfig>, ConfigError> {
        Err(ConfigError::Unimplemented {
            field_path: "typed_per_filter_config".into(),
            reason: "typed authorization overrides unsupported by this filter".into(),
        })
    }
    fn type_url(&self) -> &'static str;

    /// Parse + validate this filter's `typed_config` and return an instance factory.
    fn create(
        &self,
        config: &prost_reflect::DynamicMessage,
        ctx: &FactoryContext,
    ) -> Result<Box<dyn FilterInstanceFactory>, ConfigError>;

    /// Whether this filter can buffer response-body bytes.  The default is
    /// deliberately conservative: a newly-added filter must explicitly opt
    /// into a route's `streaming: strict` assertion after its encode path has
    /// been shown to flush through.
    ///
    /// This is a config-time capability, not a promise about one particular
    /// request. A filter that conditionally buffers still returns `true`.
    fn may_buffer_response(&self) -> bool {
        true
    }

    /// Parse per-route overrides. Default: this filter has no per-route config.
    fn parse_per_route(
        &self,
        _config: &prost_reflect::DynamicMessage,
    ) -> Result<Arc<dyn PerRouteConfig>, ConfigError> {
        Err(ConfigError::Unimplemented {
            field_path: "per-route config".to_string(),
            reason: "this filter has no per-route config".to_string(),
        })
    }
}

/// Registry mapping extension type URLs to factories — mirrors Envoy's extension
/// registry; used identically by bootstrap parsing and xDS.
#[derive(Default)]
pub struct FilterRegistry {
    factories: HashMap<&'static str, Arc<dyn HttpFilterFactory>>,
}

impl FilterRegistry {
    pub fn register(&mut self, factory: Arc<dyn HttpFilterFactory>) {
        let url = factory.type_url();
        let previous = self.factories.insert(url, factory);
        // Duplicate registration is a programmer error, not a config error.
        assert!(
            previous.is_none(),
            "duplicate filter registration for {url}"
        );
    }

    pub fn get(&self, type_url: &str) -> Option<&Arc<dyn HttpFilterFactory>> {
        self.factories.get(type_url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_or_try_init_builds_once_and_returns_same_arc() {
        // Same scope, same type_url -- one singleton, `init` runs once. This
        // is the W1/W2 per-worker property: every worker's `create` call for
        // one chain shares one `FactoryContext::scope`, so this is the shape
        // that must NOT regress when a second axis (scope) is added to the key.
        let state = SharedFactoryState::default();
        let calls = std::cell::Cell::new(0);
        let first = state
            .get_or_try_init("scope-a", "name-a", "k", || {
                calls.set(calls.get() + 1);
                Ok(Arc::new(42u32) as Arc<dyn Any + Send + Sync>)
            })
            .expect("first init succeeds");
        let second = state
            .get_or_try_init("scope-a", "name-a", "k", || {
                calls.set(calls.get() + 1);
                Ok(Arc::new(99u32) as Arc<dyn Any + Send + Sync>)
            })
            .expect("second call succeeds without re-running init");
        assert_eq!(
            calls.get(),
            1,
            "init must only run once for the same (scope, type_url)"
        );
        assert!(Arc::ptr_eq(&first, &second));
        let downcast = first.downcast::<u32>().expect("stored value was a u32");
        assert_eq!(*downcast, 42);
    }

    #[test]
    fn different_type_urls_build_independently() {
        let state = SharedFactoryState::default();
        let a = state
            .get_or_try_init("scope", "name", "a", || {
                Ok(Arc::new(1u32) as Arc<dyn Any + Send + Sync>)
            })
            .expect("init a succeeds");
        let b = state
            .get_or_try_init("scope", "name", "b", || {
                Ok(Arc::new(2u32) as Arc<dyn Any + Send + Sync>)
            })
            .expect("init b succeeds");
        assert_eq!(*a.downcast::<u32>().unwrap(), 1);
        assert_eq!(*b.downcast::<u32>().unwrap(), 2);
    }

    /// Two different scopes, same type_url -- two DIFFERENT singletons, and
    /// `init` runs twice. This is the bug this task fixes: before the
    /// `(scope, type_url)` key, this test's second `get_or_try_init` would
    /// have returned the FIRST scope's value without running its own `init`
    /// at all -- exactly the silent-discard shape found on the auth path
    /// (two listeners each configuring `llmproxy.auth` colliding on one
    /// `type_url`-only slot).
    #[test]
    fn different_scopes_build_independently_even_with_the_same_type_url() {
        let state = SharedFactoryState::default();
        let calls = std::cell::Cell::new(0);
        let a = state
            .get_or_try_init("scope-a", "name-a", "k", || {
                calls.set(calls.get() + 1);
                Ok(Arc::new(1u32) as Arc<dyn Any + Send + Sync>)
            })
            .expect("init for scope-a succeeds");
        let b = state
            .get_or_try_init("scope-b", "name-b", "k", || {
                calls.set(calls.get() + 1);
                Ok(Arc::new(2u32) as Arc<dyn Any + Send + Sync>)
            })
            .expect("init for scope-b succeeds");
        assert_eq!(
            calls.get(),
            2,
            "each scope must run its own init exactly once, even though both use type_url \"k\""
        );
        assert!(
            !Arc::ptr_eq(&a, &b),
            "scope-a and scope-b must resolve to two DIFFERENT singleton instances"
        );
        assert_eq!(*a.downcast::<u32>().unwrap(), 1);
        assert_eq!(*b.downcast::<u32>().unwrap(), 2);
    }

    #[test]
    fn get_is_none_before_init_and_some_after() {
        let state = SharedFactoryState::default();
        assert!(state.get("scope", "k").is_none());
        state
            .get_or_try_init("scope", "name", "k", || {
                Ok(Arc::new(7u32) as Arc<dyn Any + Send + Sync>)
            })
            .expect("init succeeds");
        let found = state
            .get("scope", "k")
            .expect("singleton present after init");
        assert_eq!(*found.downcast::<u32>().unwrap(), 7);
    }

    #[test]
    fn get_across_scopes_distinguishes_absent_unique_and_ambiguous() {
        let state = SharedFactoryState::default();
        assert!(state
            .get_across_scopes("k")
            .expect("no scope registered yet")
            .is_none());

        state
            .get_or_try_init("scope-a", "name-a", "k", || {
                Ok(Arc::new(1u32) as Arc<dyn Any + Send + Sync>)
            })
            .expect("init for scope-a succeeds");
        let unique = state
            .get_across_scopes("k")
            .expect("exactly one scope registered is unambiguous")
            .expect("must be Some once one scope has registered");
        assert_eq!(*unique.downcast::<u32>().unwrap(), 1);

        state
            .get_or_try_init("scope-b", "name-b", "k", || {
                Ok(Arc::new(2u32) as Arc<dyn Any + Send + Sync>)
            })
            .expect("init for scope-b succeeds");
        let scopes = state
            .get_across_scopes("k")
            .expect_err("two scopes registered under the same type_url must be ambiguous");
        assert_eq!(
            scopes,
            vec!["scope-a".to_string(), "scope-b".to_string()],
            "the ambiguity error must name every scope that registered a singleton"
        );
    }

    /// `get_by_name` resolves the same `Arc` `get` returns for
    /// the matching scope, and a DIFFERENT `stat_prefix` finds nothing --
    /// this is the property the admin server's scoped endpoints
    /// (`/chains/{stat_prefix}/...`) depend on to land a write in the right
    /// chain's control plane and not merely "some" chain's.
    #[test]
    fn get_by_name_resolves_the_same_arc_as_scoped_get_and_nothing_for_a_different_name() {
        let state = SharedFactoryState::default();
        let built = state
            .get_or_try_init("listener 'l1' filter_chains[0]", "chain-a", "k", || {
                Ok(Arc::new(7u32) as Arc<dyn Any + Send + Sync>)
            })
            .expect("init succeeds");

        let by_name = state
            .get_by_name("chain-a", "k")
            .expect("stat_prefix \"chain-a\" registered a singleton for \"k\"");
        assert!(
            Arc::ptr_eq(&built, &by_name),
            "get_by_name must resolve the SAME Arc get_or_try_init returned"
        );

        assert!(
            state.get_by_name("chain-b", "k").is_none(),
            "a different stat_prefix must not resolve chain-a's singleton"
        );
        assert!(
            state.get_by_name("chain-a", "other-type-url").is_none(),
            "a different type_url under the same stat_prefix must not resolve"
        );
    }

    /// ADR-0006 §2 plumbing: a filter factory reaches the process's node id
    /// through `FactoryContext::node_id()`, which must return exactly what
    /// `SharedFactoryState::for_node` was constructed with.
    #[test]
    fn factory_context_node_id_returns_what_shared_state_was_built_with() {
        let ctx = FactoryContext {
            shared: Arc::new(SharedFactoryState::for_node("replica-7".to_string())),
            ..Default::default()
        };
        assert_eq!(ctx.node_id(), "replica-7");
    }

    /// `::default()` (used by ~15 other test sites in this crate and its
    /// dependents) must keep yielding an empty node id, not panic or require
    /// a node identity -- see the field's own doc for why that is by design.
    #[test]
    fn shared_factory_state_default_has_empty_node_id() {
        assert_eq!(SharedFactoryState::default().node_id(), "");
    }
}
