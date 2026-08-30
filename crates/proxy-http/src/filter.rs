//! The HTTP filter API — a Rust mirror of Envoy's `envoy/http/filter.h`, with the
//! exact iteration semantics specified in internal-docs/IMPLEMENTATION_PLAN.md Appendix S2.
//!
//! This is a frozen shared surface (ground rule #4): the filter manager (WP-11),
//! the router (WP-13), the WP-31/32 filter batches, and the Lane H LLM filters all
//! code against these types. Changing a signature here requires cross-lane review.
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

/// A cloneable handle that resumes a decode-direction `StopAll*` hold from
/// OUTSIDE callback context (WP-11 chunk 4 — S2.2's "out-of-band continue"
/// case, the one thing [`DecoderCallbacks::continue_decoding`] can't do,
/// since that method only exists on the callbacks borrow, which does not
/// outlive the callback that received it). A filter that stops all
/// iteration to wait on work that resolves independently of
/// [`HttpFilter::poll_pending`] (a webhook callback, a timer, some other
/// out-of-band event) stashes this handle during the callback and calls
/// [`Self::continue_decoding`] on it whenever that work finishes — possibly
/// long after the callback that produced it has returned.
///
/// Rust note: `Rc<tokio::sync::Notify>`, not `Arc` — the filter manager is
/// per-worker and single-threaded (`ChainCtx` holds `Rc<RefCell<StreamInfo>>`
/// for the identical reason, ADR-0003), so this handle is `!Send` by design
/// and never needs to cross a thread. `Notify` specifically (not a plain
/// `bool` flag) because it **stores a permit**: a `notify_one()` that lands
/// before the driver ever awaits `notified()` is not lost — the very next
/// `.await` on it resolves immediately instead of parking. That is exactly
/// the race this handle has to be safe against: a resume that arrives while
/// the driver is still between callbacks (not yet parked) must not
/// deadlock the stream by dropping the wakeup on the floor.
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

    /// Resume iteration at the NEXT filter, replaying buffered body then trailers.
    fn continue_decoding(&mut self);

    /// A cloneable handle that can call the equivalent of
    /// [`Self::continue_decoding`] from OUTSIDE callback context (WP-11
    /// chunk 4) — see [`DecodeContinueHandle`]'s doc for the whole
    /// out-of-band-continue story.
    ///
    /// Rust note: defaulted (like [`Self::modify_decoded_headers`] and
    /// [`EncoderCallbacks::per_route_config`]) so existing test-double
    /// implementors of this trait outside this increment's scope keep
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
    /// (WP-45 increment 2a — the seam a decode filter needs to fix up
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
    /// itself** (WP-45 increment 2b): `decode_headers` already hands the
    /// filter a direct `&mut RequestHeaders` parameter that IS the request
    /// head, and Rust's aliasing rules mean this callback cannot also hold a
    /// second live `&mut` to that same value while the filter is still
    /// holding the first one — there is no clone-free way to give both
    /// access at once, and a clone-based workaround is exactly what
    /// reintroduced the increment 2a data-loss bug this increment fixes (see
    /// `filter_manager::tests::probe_direct_and_seam_mutations_coexist`). A
    /// filter running in `decode_headers` should mutate its `headers`
    /// parameter directly instead — it needs no seam there. `decode_data`
    /// and `decode_trailers` (WP-45's actual case: the decision to splice
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
    /// `DecoderCallbacks` already has test-double implementors outside this
    /// increment's scope that this change must not force edits onto; the
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
    /// CALLING filter for this stream's route, or `None` (ADR-0004 step 4
    /// increment 2).
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
    /// `EncoderCallbacks` already has test-double implementors outside this
    /// increment's scope (`proxy-filters`, `proxy-core`) that this change
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
#[derive(Default)]
pub struct SharedFactoryState {
    singletons: Mutex<HashMap<&'static str, Arc<dyn Any + Send + Sync>>>,
}

impl SharedFactoryState {
    /// Return the singleton under `key`, building and inserting it via `init`
    /// on the first call for that key. Concurrent first-callers (workers build
    /// their chains on separate runtimes) serialize on the lock; exactly one
    /// runs `init`, the rest receive its result. `init` MUST NOT call back
    /// into this method (it runs while the lock is held).
    pub fn get_or_try_init(
        &self,
        key: &'static str,
        init: impl FnOnce() -> Result<Arc<dyn Any + Send + Sync>, ConfigError>,
    ) -> Result<Arc<dyn Any + Send + Sync>, ConfigError> {
        let mut guard = self
            .singletons
            .lock()
            .expect("SharedFactoryState mutex poisoned");
        if let Some(existing) = guard.get(key) {
            return Ok(Arc::clone(existing));
        }
        let built = init()?;
        guard.insert(key, Arc::clone(&built));
        Ok(built)
    }

    /// Read a previously-initialized singleton without building one — used by
    /// the control side (admin server, later increment) to reach an instance a
    /// worker's factory built. `None` until the first `get_or_try_init`.
    pub fn get(&self, key: &'static str) -> Option<Arc<dyn Any + Send + Sync>> {
        self.singletons
            .lock()
            .expect("SharedFactoryState mutex poisoned")
            .get(key)
            .map(Arc::clone)
    }
}

/// Context handed to factories at config time. Carries the per-serve shared
/// singleton slot ([`SharedFactoryState`]); a stateless filter ignores it.
/// TODO(WP-11): stats scope, runtime.
#[derive(Default)]
pub struct FactoryContext {
    pub shared: Arc<SharedFactoryState>,
}

/// Created once per (filter config, listener); creates per-stream instances.
pub trait FilterInstanceFactory: Send + Sync {
    fn create_filter(&self) -> Box<dyn HttpFilter>;
}

/// One registered filter implementation, keyed by its Envoy extension type URL
/// (e.g. `type.googleapis.com/envoy.extensions.filters.http.router.v3.Router`).
/// Lane H extensions register under `type.llmproxy.dev/...`.
pub trait HttpFilterFactory: Send + Sync {
    fn type_url(&self) -> &'static str;

    /// Parse + validate this filter's `typed_config` and return an instance factory.
    fn create(
        &self,
        config: &prost_reflect::DynamicMessage,
        ctx: &FactoryContext,
    ) -> Result<Box<dyn FilterInstanceFactory>, ConfigError>;

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
/// registry; used identically by bootstrap parsing and xDS (WP-11).
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
        let state = SharedFactoryState::default();
        let calls = std::cell::Cell::new(0);
        let first = state
            .get_or_try_init("k", || {
                calls.set(calls.get() + 1);
                Ok(Arc::new(42u32) as Arc<dyn Any + Send + Sync>)
            })
            .expect("first init succeeds");
        let second = state
            .get_or_try_init("k", || {
                calls.set(calls.get() + 1);
                Ok(Arc::new(99u32) as Arc<dyn Any + Send + Sync>)
            })
            .expect("second call succeeds without re-running init");
        assert_eq!(calls.get(), 1, "init must only run once for the same key");
        assert!(Arc::ptr_eq(&first, &second));
        let downcast = first.downcast::<u32>().expect("stored value was a u32");
        assert_eq!(*downcast, 42);
    }

    #[test]
    fn different_keys_build_independently() {
        let state = SharedFactoryState::default();
        let a = state
            .get_or_try_init("a", || Ok(Arc::new(1u32) as Arc<dyn Any + Send + Sync>))
            .expect("init a succeeds");
        let b = state
            .get_or_try_init("b", || Ok(Arc::new(2u32) as Arc<dyn Any + Send + Sync>))
            .expect("init b succeeds");
        assert_eq!(*a.downcast::<u32>().unwrap(), 1);
        assert_eq!(*b.downcast::<u32>().unwrap(), 2);
    }

    #[test]
    fn get_is_none_before_init_and_some_after() {
        let state = SharedFactoryState::default();
        assert!(state.get("k").is_none());
        state
            .get_or_try_init("k", || Ok(Arc::new(7u32) as Arc<dyn Any + Send + Sync>))
            .expect("init succeeds");
        let found = state.get("k").expect("singleton present after init");
        assert_eq!(*found.downcast::<u32>().unwrap(), 7);
    }
}
