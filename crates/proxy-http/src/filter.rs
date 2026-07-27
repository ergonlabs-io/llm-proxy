//! The HTTP filter API — a Rust mirror of Envoy's `envoy/http/filter.h`, with the
//! exact iteration semantics specified in IMPLEMENTATION_PLAN.md Appendix S2.
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

use std::collections::HashMap;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use http::{HeaderMap, Method, StatusCode, Uri};
use proxy_config::ir::RouteEntry;
use proxy_config::ConfigError;

use crate::stream_info::StreamInfo;

/// Request head. Pseudo-header data (`:method`, `:path`, `:authority`) is carried
/// in the typed fields; `headers` holds regular headers only.
#[derive(Debug)]
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

    /// Append to the buffered body (legal from headers/data/trailers callbacks).
    fn add_decoded_data(&mut self, data: Bytes, streaming: bool);

    /// Deliver data directly to subsequent filters, outside callback context
    /// (pairs with `ContinueAndDontEndStream`).
    fn inject_decoded_data_to_filter_chain(&mut self, data: Bytes, end_stream: bool);

    fn decoding_buffer(&self) -> Option<&BufferedBody>;

    /// Only legal before any data has been continued past this filter (S2.7).
    fn modify_decoding_buffer(&mut self, f: &mut dyn FnMut(&mut BytesMut));

    /// The cached route (S2.8). Resolved lazily on first access.
    fn route(&self) -> Option<Arc<RouteEntry>>;

    /// S2.8: the route cache is NOT auto-invalidated — any filter mutating
    /// routing-relevant headers must call this (differential fixture required).
    fn clear_route_cache(&mut self);

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
}

/// Marker trait for parsed per-route filter config (`typed_per_filter_config`).
pub trait PerRouteConfig: Send + Sync {}

/// Context handed to factories at config time. TODO(WP-11): stats scope, runtime.
pub struct FactoryContext {}

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
