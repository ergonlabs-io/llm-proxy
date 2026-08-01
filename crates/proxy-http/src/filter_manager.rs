//! WP-11: the HTTP filter manager — drives the S2 iteration state machine over
//! the frozen [`crate::filter`] API and bridges it to the codec's
//! [`StreamHandler`] seam.
//!
//! # Scope so far (chunks 1-3)
//!
//! The **decode** (request) direction stays fully buffered: it collects the
//! whole request body, then runs the decoder chain (config order). LLM request
//! bodies are small JSON, so there's no time-to-first-byte pressure there.
//!
//! The **encode** (response) direction is now **streaming** (chunk 3): the
//! manager no longer collects the upstream response before encoding it. It
//! runs the encode *header* phase (async — a header hold may need to consume
//! upstream frames to resolve, S2.2), then returns a response whose body is a
//! [`StreamingEncoder`] — a hand-rolled [`hyper::body::Body`] that pulls
//! frames from the upstream body on demand, running the encoder chain
//! (**reverse** config order, S2.1) over each one as it arrives. This is what
//! makes time-to-first-token (WP-33) possible: bytes flow to the downstream
//! connection as soon as a filter lets them through, without waiting for the
//! upstream response to finish.
//!
//! S2 mechanics covered:
//!
//! - S2.1 ordering (decode forward, encode reverse) and per-stream teardown
//!   (`on_destroy`, reverse creation order) — now driven by [`Drop`], since a
//!   streaming response means filters live until the stream actually ends, not
//!   until `run()` returns;
//! - S2.2/S2.3 `Continue`, `StopIteration`/stop-all header-hold + resume (via
//!   `continue_*()` or a `Continue` from the same filter's data callback), and
//!   the buffering statuses, now genuinely incremental on the encode side (a
//!   held filter keeps seeing new frames, not a single fully-buffered chunk);
//! - S2.4 trailers, including "queue behind buffered data" on encode;
//! - `add_*_data` / `*coding_buffer` / `modify_*_buffer` buffer APIs (S2.7);
//! - buffer-limit overflow → **413** (decode) / **500** (encode, only while
//!   headers are still held) / mid-stream truncation with an error (encode,
//!   once headers have already been forwarded — a 500 can no longer be sent).
//!
//! `send_local_reply` (S2.5) now lands too: before response headers have been
//! forwarded downstream, it synthesizes a response and drives it through the
//! encoder chain via the exact same [`encode_headers_phase`] +
//! [`StreamingEncoder`] machinery a normal response uses — an encoder filter
//! (token metering, access logging, ...) can't tell a local reply from an
//! ordinary one. The manager's own failure paths (decode buffer overflow →
//! 413, a request body read error → 400, an encode-header-phase buffer
//! overflow → 500) are routed through the same [`respond_with_local_reply`]
//! helper, for the same reason: no response should bypass the chain filters
//! were installed to observe.
//!
//! Deferred to later chunks:
//! watermark backpressure (treated as plain buffering for now); 1xx (S2.6);
//! `inject_*_to_filter_chain` and `ContinueAndDontEndStream` (S2.7); lazy route
//! resolution + cache (S2.8, needs the WP-12 route table); resetting the
//! downstream stream when a filter stalls forever past end-of-stream, or when
//! an encode header-hold is never resolved before the upstream response ends
//! (both noted at their call sites); an out-of-callback `continue_encoding()`
//! that could wake a *pending* `poll_frame` (today it only matters if observed
//! synchronously inside a callback — there's no waker registered for a filter
//! that decides to continue later, e.g. after async work); a genuine stream
//! **reset** for `send_local_reply` called after response headers have
//! already been forwarded — we have no reset primitive through the body seam
//! yet, so that case terminates the body with a [`BodyError`] instead (noted
//! at [`DecoderCallbacksAdapter::send_local_reply`]). The ~60-case S2
//! conformance suite (chunk 2, already landed for decode) is what will keep
//! pinning every corner as the remaining items land.
//!
//! # The encode per-position state machine
//!
//! Every frame — real or the synthetic end-of-stream flush — walks the encode
//! chain starting at position **0**, always (never resuming mid-chain from
//! wherever some other position happens to be stopped: that was a real bug,
//! see the `PositionState` doc comment). A frame flows forward until it hits a
//! position that is currently stopped; that's where it accumulates. Because
//! frames now genuinely walk from the front every time, more than one
//! position can be stopped simultaneously (an early filter buffering while a
//! later one is also buffering), so each position gets its **own** buffer
//! (`ctx.encode.positions: Vec<PositionState>`, indexed by position, not by
//! filter index — see [`StreamingEncoder`]'s doc comment for what "position"
//! means) instead of one buffer shared by the whole direction.
//!
//! # The borrow problem (and why this compiles without `unsafe`)
//!
//! A filter callback receives `&mut dyn DecoderCallbacks` — the manager — while
//! the manager is also holding `&mut filters[i]` to make the call. Envoy uses
//! raw back-pointers here. We instead **split storage**: the filter `Vec` and
//! the mutable [`ChainCtx`] (buffers, stream info, continuation flags) are
//! distinct fields, and the message head is passed as its own `&mut`. So one
//! call site borrows three *disjoint* things — `&mut filters[i]`, `&mut head`,
//! and a callbacks adapter that borrows only `&mut ctx` — which the borrow
//! checker accepts. It's sound because the callbacks only ever *record* state in
//! `ctx` (continue flags, appended buffer bytes) that the driver acts on **after
//! the callback returns**; a callback never re-enters another filter.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Instant, SystemTime};

use bytes::{Bytes, BytesMut};
use http::HeaderMap;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Body, Frame};

use proxy_config::ir::{AccessLogIR, PerFilterConfig, RouteEntry, RouteTable};
use proxy_config::ConfigError;

use crate::access_logging::{
    snapshot_request, AccessLogContext, AccessLoggerRuntime, LoggingBody, RequestSnapshot,
};
use crate::filter::{
    BufferedBody, DecoderCallbacks, EncoderCallbacks, FilterDataStatus, FilterHeadersStatus,
    FilterInstanceFactory, HeaderMutationFn, HttpFilter, HttpFilterFactory, PerRouteConfig,
    RequestHeaders, RequestTrailers, ResponseHeaders, ResponseTrailers,
    TerminalFilterInstanceFactory, TerminalHttpFilter,
};
use crate::handler::{
    local_boxed, BodyError, HttpRequestParts, HttpResponseParts, StreamBody as SeamBody,
    StreamHandler,
};
use crate::route::{match_route, RouteMatch, RouteRequest};
use crate::stream_info::StreamInfo;

/// Default per-direction buffer limit (Envoy's
/// `per_connection_buffer_limit_bytes` default is 1 MiB). Overflow of a filter
/// that requested buffering yields 413 on decode / 500 on encode.
pub const DEFAULT_BUFFER_LIMIT: usize = 1 << 20;

/// One `http_filters` chain entry, as building a [`FilterChainHandler`] with
/// `typed_per_filter_config` resolution (ADR-0004 step 4 increment 2) needs
/// it: the Envoy filter name (`typed_per_filter_config`'s map key), the
/// per-stream instance factory (unchanged — what `factories` alone used to
/// carry), and the REGISTERED [`HttpFilterFactory`] itself, needed once at
/// construction to resolve any `typed_per_filter_config` entry naming this
/// filter through `HttpFilterFactory::parse_per_route`.
///
/// Rust note: not retained after construction — [`FilterChainHandler::new_with_filters`]
/// consumes a `Vec` of these and keeps only the already-resolved
/// [`PerRouteTable`] plus the plain instance factories, exactly like
/// [`FilterChainHandler::new`] always has.
pub struct ConfiguredHttpFilter {
    pub name: String,
    pub instance_factory: Arc<dyn FilterInstanceFactory>,
    pub factory: Arc<dyn HttpFilterFactory>,
}

/// Resolved `typed_per_filter_config` for one HCM's filter chain (ADR-0004
/// step 4 increment 2), built once at [`FilterChainHandler`] construction —
/// never re-parsed per stream, mirroring how Envoy validates this against
/// the real filter chain when it's built. Every row is `[filter_index]`
/// -indexed, in the SAME config order `FilterChainHandler::factories` uses
/// (the router is never a row here: it's the HCM's terminal filter, not one
/// of the ordinary chain filters `build_per_route_table` resolves against).
#[derive(Default)]
struct PerRouteTable {
    /// `[route.route_index][filter_index]`.
    route: Vec<Vec<Option<Arc<dyn PerRouteConfig>>>>,
    /// `[vhost position in `RouteTable::virtual_hosts`][filter_index]`.
    virtual_host: Vec<Vec<Option<Arc<dyn PerRouteConfig>>>>,
    /// `[filter_index]`, from `RouteConfiguration.typed_per_filter_config`
    /// (the least-specific level).
    route_config: Vec<Option<Arc<dyn PerRouteConfig>>>,
    /// `route_index -> vhost position`, precomputed here because
    /// `proxy_config::ir::RouteEntry` doesn't carry its owning vhost's index
    /// — this is the cheap alternative to scanning `RouteTable::virtual_hosts`
    /// on every [`per_route_config_for`] call.
    route_to_vhost: Vec<usize>,
}

// Rust note: manual `Debug`, not `#[derive(Debug)]` -- `Arc<dyn PerRouteConfig>`
// has no `Debug` bound (the trait only requires `Send + Sync`, deliberately;
// see its doc), so a derive can't compile. Tests only need this to satisfy
// `Result::expect_err`'s `T: Debug` bound; the row contents don't matter for
// that, so this just reports shape (row counts), not content.
impl std::fmt::Debug for PerRouteTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PerRouteTable")
            .field("route_rows", &self.route.len())
            .field("virtual_host_rows", &self.virtual_host.len())
            .field("route_config_row_len", &self.route_config.len())
            .finish()
    }
}

impl PerRouteTable {
    /// Look up the most specific override for `filter_index` given the
    /// stream's resolved `route` — route > virtual host > route
    /// configuration (Envoy's `mostSpecificPerFilterConfig`). `.get(..)`
    /// throughout (never direct indexing): an empty [`PerRouteTable::default`]
    /// (built by [`FilterChainHandler::new`], which has no filter NAMES to
    /// resolve against) must behave as "no override anywhere", not panic.
    fn lookup(&self, route: &RouteEntry, filter_index: usize) -> Option<Arc<dyn PerRouteConfig>> {
        if let Some(cfg) = self
            .route
            .get(route.route_index)
            .and_then(|row| row.get(filter_index))
            .and_then(|slot| slot.clone())
        {
            return Some(cfg);
        }
        if let Some(cfg) = self
            .route_to_vhost
            .get(route.route_index)
            .and_then(|&vhost_idx| self.virtual_host.get(vhost_idx))
            .and_then(|row| row.get(filter_index))
            .and_then(|slot| slot.clone())
        {
            return Some(cfg);
        }
        self.route_config
            .get(filter_index)
            .and_then(|slot| slot.clone())
    }
}

/// Resolve one `typed_per_filter_config` map (one of the three levels) into
/// a `[filter_index]`-indexed row, validating every entry against the
/// ACTUAL chain (ground rule #1 — a name/shape mismatch is a config error,
/// not a silent no-op):
///
/// - a name absent from `names` is an error naming the filter and
///   `context`, unless the entry's `is_optional` is set (then it's skipped);
/// - `disabled: true` is an `Unimplemented` error (not yet supported —
///   skipping a filter per-route requires the manager to act on it at run
///   time, which is a later increment); never silently dropped;
/// - otherwise the entry's config is handed to that filter's
///   `HttpFilterFactory::parse_per_route`; an `Err` (including the trait's
///   own default — "this filter has no per-route config") propagates as-is
///   unless `is_optional` is set, in which case it's skipped.
fn resolve_per_filter_row(
    entries: &BTreeMap<String, PerFilterConfig>,
    names: &[String],
    factories: &[Arc<dyn HttpFilterFactory>],
    filter_count: usize,
    context: &str,
) -> Result<Vec<Option<Arc<dyn PerRouteConfig>>>, ConfigError> {
    let mut row: Vec<Option<Arc<dyn PerRouteConfig>>> = vec![None; filter_count];
    for (filter_name, cfg) in entries {
        let field_path = format!("{context}[{filter_name}]");
        let Some(idx) = names.iter().position(|name| name == filter_name) else {
            if cfg.is_optional {
                continue;
            }
            return Err(ConfigError::Validation {
                field_path,
                rule: format!(
                    "filter '{filter_name}' is not present in this HTTP filter chain \
                     (set `is_optional: true` on this override to ignore it)"
                ),
            });
        };
        if cfg.disabled {
            return Err(ConfigError::Unimplemented {
                field_path,
                reason: format!(
                    "disabling filter '{filter_name}' for this route/virtual-host/\
                     route-configuration (`typed_per_filter_config.disabled`) is not \
                     yet implemented — the filter manager cannot skip a filter at run \
                     time yet"
                ),
            });
        }
        let config = cfg
            .config
            .as_ref()
            .ok_or_else(|| ConfigError::InvalidValue {
                field_path: field_path.clone(),
                reason: "no config present and `disabled` is not set".to_string(),
            })?;
        match factories[idx].parse_per_route(config) {
            Ok(parsed) => row[idx] = Some(parsed),
            // `is_optional` means "ignore this override if the filter does not
            // SUPPORT per-route config" -- it does not mean "ignore any error".
            // `HttpFilterFactory::parse_per_route`'s default body is what
            // reports non-support, and it reports it as `Unimplemented`; every
            // other variant means the filter does support per-route config and
            // rejected THIS config. Swallowing those under `is_optional` would
            // silently drop a malformed override on a filter that would have
            // honored a correct one -- ground rule #1, and not what Envoy does
            // either.
            Err(ConfigError::Unimplemented { .. }) if cfg.is_optional => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(row)
}

/// Build the [`PerRouteTable`] for one HCM's filter chain (ADR-0004 step 4
/// increment 2): resolve `RouteConfiguration`/`VirtualHost`/`Route`-level
/// `typed_per_filter_config` once, at build time, against the real chain —
/// see [`resolve_per_filter_row`] for the per-entry rules. `names[i]` is
/// `factories[i]`'s Envoy filter name; both share filter index with
/// `FilterChainHandler::factories` (config order, router excluded).
fn build_per_route_table(
    names: &[String],
    factories: &[Arc<dyn HttpFilterFactory>],
    route_table: &RouteTable,
) -> Result<PerRouteTable, ConfigError> {
    let filter_count = names.len();

    let route_config = resolve_per_filter_row(
        &route_table.typed_per_filter_config,
        names,
        factories,
        filter_count,
        &format!("{}.typed_per_filter_config", route_table.name),
    )?;

    let mut virtual_host = Vec::with_capacity(route_table.virtual_hosts.len());
    let route_count = route_table.route_count();
    let mut route = vec![Vec::new(); route_count];
    let mut route_to_vhost = vec![0usize; route_count];

    for (vhost_idx, vhost) in route_table.virtual_hosts.iter().enumerate() {
        let vhost_row = resolve_per_filter_row(
            &vhost.typed_per_filter_config,
            names,
            factories,
            filter_count,
            &format!(
                "{}.virtual_hosts[{vhost_idx}] ({}).typed_per_filter_config",
                route_table.name, vhost.name
            ),
        )?;
        virtual_host.push(vhost_row);

        for route_entry in &vhost.routes {
            let row = resolve_per_filter_row(
                &route_entry.typed_per_filter_config,
                names,
                factories,
                filter_count,
                &format!(
                    "{}.virtual_hosts[{vhost_idx}].routes[route_index={}].typed_per_filter_config",
                    route_table.name, route_entry.route_index
                ),
            )?;
            route[route_entry.route_index] = row;
            route_to_vhost[route_entry.route_index] = vhost_idx;
        }
    }

    Ok(PerRouteTable {
        route,
        virtual_host,
        route_config,
        route_to_vhost,
    })
}

/// A [`StreamHandler`] that runs a request through an HTTP filter chain before
/// (and the response after) an inner terminal handler. One of these is built per
/// HTTP connection manager (see `build_hcm_handler` in proxy-core) and reused
/// across every request on the connection; a fresh set of per-stream filter
/// instances is created for each request (S2.1: "instances are per-stream").
pub struct FilterChainHandler {
    /// Config-order factories; `create_filter()` mints one instance per stream.
    factories: Vec<Arc<dyn FilterInstanceFactory>>,
    /// ADR-0004 step 3: the terminal's own factory -- mints a fresh
    /// [`TerminalHttpFilter`] instance per stream, exactly like every other
    /// filter. `Arc`, same as `factories` above: see
    /// [`TerminalFilterInstanceFactory`]'s doc -- it's config-time plumbing
    /// and carries `Send + Sync` per ADR-0003, just like `FilterInstanceFactory`.
    terminal_factory: Arc<dyn TerminalFilterInstanceFactory>,
    /// S2.8 (ADR-0004 step 1): this HCM's route table -- the manager, not the
    /// router, now owns route resolution. Handed to each stream's `ChainCtx`
    /// so `DecoderCallbacks::route()` (and the terminal-request resolution in
    /// `FilterManager::run`) can match against it.
    route_table: Arc<RouteTable>,
    buffer_limit: usize,
    /// S9/HCM: generate `x-request-id` when the request lacks one (Envoy
    /// default true).
    generate_request_id: bool,
    /// S9/HCM `use_remote_address`: when true, this HCM is at the network
    /// edge -- append the downstream peer to `x-forwarded-for` and stamp
    /// `x-forwarded-proto` from our transport. Envoy default false.
    use_remote_address: bool,
    /// S9/HCM `xff_num_trusted_hops`: forwarded straight through to
    /// [`crate::headers::XffOptions`]; only meaningful when
    /// `use_remote_address` is true.
    xff_num_trusted_hops: u32,
    /// Rust note: `RefCell` (not `Mutex`) because `FilterChainHandler` is
    /// worker-local (`!Send`, ADR-0003) -- one instance per worker thread, built
    /// once at bind time, so there's no cross-thread contention to guard
    /// against, only the single-threaded aliasing rule a `Cell`/`RefCell` exists
    /// for. Seeded once per handler (`headers::seed_from_entropy`) so different
    /// workers -- and different `FilterChainHandler`s in tests -- draw
    /// independent id sequences.
    request_id_rng: std::cell::RefCell<u64>,
    /// WP-24 chunk 3, relocated from `RouterHandler` (see the module doc's
    /// note on why access logging moved up here): this HCM's configured
    /// access loggers, already resolved to open sinks -- empty when the HCM
    /// has no `access_logs`, in which case [`Self::handle`] skips the
    /// `LoggingBody` wrap entirely. `Rc` (not `Arc`): shared cheaply across
    /// every request this (`!Send`, per-worker) handler serves, never across
    /// workers.
    access_loggers: Rc<Vec<AccessLoggerRuntime>>,
    /// ADR-0004 step 4 increment 2: this HCM's resolved `typed_per_filter_config`,
    /// keyed by filter index the same way `factories` is. `Arc` (not a plain
    /// field): cloned into every stream's `ChainCtx`, same pattern as
    /// `route_table`. Built by [`Self::new_with_filters`]; [`Self::new`] has
    /// no filter NAMES to resolve against, so it always gets the empty
    /// default (`per_route_config()` then always returns `None`, this
    /// handler's pre-increment-2 behavior).
    per_route: Arc<PerRouteTable>,
}

impl FilterChainHandler {
    pub fn new(
        factories: Vec<Arc<dyn FilterInstanceFactory>>,
        terminal_factory: Arc<dyn TerminalFilterInstanceFactory>,
        route_table: Arc<RouteTable>,
        generate_request_id: bool,
        use_remote_address: bool,
        xff_num_trusted_hops: u32,
    ) -> Self {
        Self {
            factories,
            terminal_factory,
            route_table,
            buffer_limit: DEFAULT_BUFFER_LIMIT,
            generate_request_id,
            use_remote_address,
            xff_num_trusted_hops,
            request_id_rng: std::cell::RefCell::new(crate::headers::seed_from_entropy()),
            access_loggers: Rc::new(Vec::new()),
            per_route: Arc::new(PerRouteTable::default()),
        }
    }

    /// Like [`Self::new`], but resolving `access_logs` into live sinks
    /// (opening/sharing files via a fresh [`AccessLoggerRuntime`] registry
    /// scoped to this one build) -- what `proxy-core`'s `build_hcm_handler`
    /// calls, since every HCM in real config carries its own `access_logs`.
    /// Kept as a separate constructor (rather than adding a parameter to
    /// `new`) so every existing caller that has no sinks to build -- and so
    /// no `io::Error` to handle -- is unaffected. Mirrors
    /// `RouterHandler::new_with_access_logs`'s old contract, before access
    /// logging moved up here.
    pub fn new_with_access_logs(
        factories: Vec<Arc<dyn FilterInstanceFactory>>,
        terminal_factory: Arc<dyn TerminalFilterInstanceFactory>,
        route_table: Arc<RouteTable>,
        generate_request_id: bool,
        use_remote_address: bool,
        xff_num_trusted_hops: u32,
        access_logs: &[AccessLogIR],
    ) -> std::io::Result<Self> {
        let registry = proxy_observability::sink::SinkRegistry::new();
        let access_loggers = AccessLoggerRuntime::build_all(access_logs, &registry)?;
        Ok(Self {
            access_loggers: Rc::new(access_loggers),
            ..Self::new(
                factories,
                terminal_factory,
                route_table,
                generate_request_id,
                use_remote_address,
                xff_num_trusted_hops,
            )
        })
    }

    /// Like [`Self::new`], but `filters` carries each configured filter's
    /// Envoy name and registered [`HttpFilterFactory`] alongside its
    /// per-stream instance factory, so this build/rebuild also resolves
    /// `typed_per_filter_config` against the real chain (ADR-0004 step 4
    /// increment 2 -- see [`build_per_route_table`]). A resolution failure
    /// (an unknown filter name, an unimplemented `disabled`, or a filter's
    /// own `parse_per_route` rejecting its config) fails the whole build,
    /// same as any other invalid `http_filters` entry (ground rule #1: never
    /// silently drop a config field).
    pub fn new_with_filters(
        filters: Vec<ConfiguredHttpFilter>,
        terminal_factory: Arc<dyn TerminalFilterInstanceFactory>,
        route_table: Arc<RouteTable>,
        generate_request_id: bool,
        use_remote_address: bool,
        xff_num_trusted_hops: u32,
    ) -> Result<Self, ConfigError> {
        let names: Vec<String> = filters.iter().map(|f| f.name.clone()).collect();
        let http_factories: Vec<Arc<dyn HttpFilterFactory>> =
            filters.iter().map(|f| f.factory.clone()).collect();
        let per_route = build_per_route_table(&names, &http_factories, &route_table)?;
        let factories = filters.into_iter().map(|f| f.instance_factory).collect();
        Ok(Self {
            per_route: Arc::new(per_route),
            ..Self::new(
                factories,
                terminal_factory,
                route_table,
                generate_request_id,
                use_remote_address,
                xff_num_trusted_hops,
            )
        })
    }

    /// [`Self::new_with_filters`] + [`Self::new_with_access_logs`] combined —
    /// what `proxy-core`'s `build_hcm_handler` actually calls, since a real
    /// HCM carries both `http_filters` (with their names, for per-route
    /// resolution) and `access_logs`.
    pub fn new_with_filters_and_access_logs(
        filters: Vec<ConfiguredHttpFilter>,
        terminal_factory: Arc<dyn TerminalFilterInstanceFactory>,
        route_table: Arc<RouteTable>,
        generate_request_id: bool,
        use_remote_address: bool,
        xff_num_trusted_hops: u32,
        access_logs: &[AccessLogIR],
    ) -> Result<Self, ConfigError> {
        let registry = proxy_observability::sink::SinkRegistry::new();
        let access_loggers =
            AccessLoggerRuntime::build_all(access_logs, &registry).map_err(|e| {
                ConfigError::Io {
                    path: "access_logs".to_string(),
                    reason: e.to_string(),
                }
            })?;
        Ok(Self {
            access_loggers: Rc::new(access_loggers),
            ..Self::new_with_filters(
                filters,
                terminal_factory,
                route_table,
                generate_request_id,
                use_remote_address,
                xff_num_trusted_hops,
            )?
        })
    }

    pub fn with_buffer_limit(mut self, limit: usize) -> Self {
        self.buffer_limit = limit;
        self
    }
}

impl StreamHandler for FilterChainHandler {
    /// The HCM entry point: applies S9 HCM-level header behavior
    /// (`x-request-id`, XFF), builds a fresh per-stream `FilterManager`, runs
    /// it, and -- this is the single outermost exit point every response
    /// takes, including a filter-chain local reply -- wraps whatever
    /// [`FilterManager::run`] hands back in [`LoggingBody`] when this HCM has
    /// `access_logs` configured.
    ///
    /// This is where WP-24 chunk 3's access logging now lives (relocated
    /// from `RouterHandler::handle_and_log`; see [`crate::access_logging`]'s
    /// module doc for why). The nesting is `LoggingBody(StreamingEncoder(...))`
    /// -- `LoggingBody` wraps OUTSIDE the encode filter chain's own body, not
    /// inside the router's response the way the old design had it -- so a
    /// line is only ever rendered once every encode filter (and the encode
    /// chain's own end-of-stream flush) has already run, and so that a local
    /// reply synthesized by the filter chain itself (which never reaches the
    /// router terminal at all) still gets logged.
    fn handle<'a>(
        &'a self,
        mut req: HttpRequestParts,
    ) -> Pin<Box<dyn Future<Output = HttpResponseParts> + 'a>> {
        Box::pin(async move {
            // Access-log timing/downstream-address, captured up front --
            // same as the pre-relocation `RouterHandler::handle_and_log` did,
            // just one level higher (before the decode chain runs, not after
            // it) so the duration covers the whole filter-chain-plus-upstream
            // round trip, not just the part downstream of the router.
            let start_time = SystemTime::now();
            let start_instant = Instant::now();
            let downstream_remote_address = req.downstream.remote.to_string();

            // S9: apply `x-request-id` before the decode filter chain runs, so
            // every decode filter (and the router terminal) observes it. Runs
            // ahead of `FilterManager` construction rather than as a filter
            // itself -- it's an always-on HCM-level behavior, not a
            // configurable filter.
            if self.generate_request_id {
                let mut state = self.request_id_rng.borrow_mut();
                crate::headers::ensure_request_id(&mut req.head.headers, &mut || {
                    crate::headers::generate_request_id(&mut state, false)
                });
                // `state` (a `RefMut`) drops here, releasing the borrow before
                // `req` moves into `FilterManager::run` below.
            }
            // S9: at the edge (use_remote_address), append the downstream peer
            // to x-forwarded-for and stamp x-forwarded-proto from our
            // transport. Applied HCM-level, before the decode filter chain, so
            // filters and the router observe the mutated headers. A non-edge
            // (mesh/internal) HCM leaves both headers untouched — it trusts
            // the inbound values.
            if self.use_remote_address {
                let xff = crate::headers::XffOptions {
                    use_remote_address: true,
                    xff_num_trusted_hops: self.xff_num_trusted_hops,
                };
                crate::headers::apply_xff(&mut req.head.headers, req.downstream.remote.ip(), &xff);
                crate::headers::set_forwarded_proto(&mut req.head.headers, req.downstream.is_tls);
            }
            // Rust note: a fresh, `!Send` instance vector per request — filters
            // may freely hold `Rc`/`RefCell` (ADR-0003).
            let filters: Vec<Box<dyn HttpFilter>> =
                self.factories.iter().map(|f| f.create_filter()).collect();
            // ADR-0004 step 3: the terminal instance is minted LAST, after
            // every configured filter -- it's created and destroyed exactly
            // like any other filter instance (S2.1: reverse creation order),
            // just via its own factory type since `TerminalHttpFilter` isn't
            // `HttpFilter`-uniform (it also exposes `respond`).
            let terminal = self.terminal_factory.create_terminal_filter();
            // The one `StreamInfo` for this stream (Envoy's model, module
            // doc): created once here, cloned (cheap `Rc` bump) into `ctx`
            // for every filter (including the terminal, which reads it
            // through `DecoderCallbacks::stream_info()` like any other
            // filter). Also kept here, uncloned, for the access-log wrap
            // below -- `LoggingBody` needs to read the SAME `StreamInfo`
            // every filter (including an encode filter's end-of-stream
            // callback) wrote into.
            let stream_info = Rc::new(RefCell::new(StreamInfo::default()));
            let mgr = FilterManager {
                filters,
                ctx: ChainCtx::new(stream_info.clone())
                    .with_route_table(self.route_table.clone())
                    .with_per_route(self.per_route.clone()),
                terminal,
                buffer_limit: self.buffer_limit,
            };
            // Rust note: `mgr` is still a plain local value here (not yet
            // moved into `run()`), so its `ctx.request_headers_snapshot` --
            // an `Rc<RefCell<Option<HeaderMap>>>` `ChainCtx::new` mints
            // internally -- can be cloned out now and read back after `run()`
            // returns, without changing `run()`'s own return type (which
            // every direct `FilterManager` test below also relies on).
            let request_headers_snapshot = mgr.ctx.request_headers_snapshot.clone();
            let resp = mgr.run(req).await;

            if self.access_loggers.is_empty() {
                return resp;
            }

            // Rust note: `.take()` both reads the snapshot out and leaves
            // `None` behind -- there's nothing else left to read it after
            // this. `unwrap_or_default()` only matters if every path inside
            // `run()` somehow skipped setting it, which none do (module doc
            // on `ChainCtx::request_headers_snapshot`'s field).
            let request = request_headers_snapshot
                .borrow_mut()
                .take()
                .unwrap_or_default();
            let log_ctx = AccessLogContext {
                loggers: self.access_loggers.clone(),
                stream_info,
                start_time,
                start_instant,
                request,
                response_headers: resp.head.headers.clone(),
                response_code: resp.head.status.as_u16(),
                downstream_remote_address,
            };
            HttpResponseParts {
                head: resp.head,
                body: local_boxed(LoggingBody::new(resp.body, log_ctx)),
            }
        })
    }
}

/// Per-direction iteration bookkeeping the callbacks record into and the driver
/// reads back after each callback returns. Decode stays fully buffered (module
/// doc), so one shared buffer per direction is still correct here.
#[derive(Default)]
struct DirectionState {
    /// Filter-manager buffer for this direction (S2.7).
    buffer: BufferedBody,
    /// Set by `continue_decoding()` / `continue_encoding()`; the driver clears
    /// it once observed.
    continue_requested: bool,
    /// S2.7: the filter index the driver is *currently* invoking a decode
    /// callback on, so `inject_decoded_data_to_filter_chain` knows which
    /// position to deliver "after" — the callback adapter only borrows `ctx`
    /// (module doc), not the filter index, so the driver stashes it here right
    /// before every call. Only meaningful during a callback; stale otherwise.
    current_idx: usize,
    /// S2.7: out-of-band injections recorded by
    /// `inject_decoded_data_to_filter_chain`, each `(originating filter
    /// index, data, end_stream)`. Drained by the decode driver
    /// (`drain_decode_injections`) immediately after the injecting callback
    /// returns — delivered to filters strictly AFTER the originator (never
    /// re-entering it), and without touching `continue_requested`, so
    /// injecting never itself resumes the originator's own held iteration.
    injected: VecDeque<(usize, Bytes, bool)>,
}

/// Encode-side counterpart to [`DirectionState`]. Unlike decode, encode is
/// streaming and — once a frame can reach a stopped position no matter what
/// stopped earlier (the fix for the position-skipping bug) — more than one
/// position can be stopped at once, so it needs one buffer **per position**
/// rather than one shared buffer for the whole direction. See
/// [`PositionState`]'s doc comment for the invariant this relies on.
#[derive(Default)]
struct EncodeState {
    /// Set by `continue_encoding()`; the driver clears it once observed. Not
    /// per-position: only one filter call is ever in flight at a time, so
    /// there's nothing to disambiguate.
    continue_requested: bool,
    /// Indexed by *position* (`p`), not filter index — see
    /// [`StreamingEncoder`]'s doc comment. Sized once the per-stream filter
    /// instances exist (in [`encode_headers_phase`]; `ChainCtx::new` doesn't
    /// know `n` yet).
    positions: Vec<PositionState>,
    /// S2.7: out-of-band injections queued by
    /// `inject_encoded_data_to_filter_chain`, reusing [`PendingFrame`]'s
    /// `(data, end_stream, start_pos)` shape — injection and a header-hold's
    /// leftover frame have identical delivery semantics: resume at a specific
    /// position, honoring that position's (and everything after it's)
    /// existing `StopKind`/buffer state, never touching earlier positions.
    /// Drained into whichever `pending` queue is currently in scope
    /// ([`encode_headers_phase`]'s local one, or
    /// [`StreamingEncoder::pending`]) immediately after the injecting
    /// callback returns.
    injected: VecDeque<PendingFrame>,
}

/// Split-storage counterpart to the filter `Vec`: everything a callback may
/// touch. Kept separate from the filters so a callback adapter can borrow this
/// while the driver still holds `&mut filters[i]` (see the module doc).
struct ChainCtx {
    decode: DirectionState,
    encode: EncodeState,
    /// Rust note: `Rc<RefCell<StreamInfo>>` — shared, interior-mutable
    /// ownership. This is the ONE `StreamInfo` for the whole stream: the
    /// filter manager writes into it here, every filter callback (through
    /// [`DecoderCallbacksAdapter::stream_info`] /
    /// [`EncoderCallbacksAdapter::stream_info`]) borrows the *same* `Rc`
    /// clone, and it's handed to the router terminal via
    /// [`crate::handler::HttpRequestParts::stream_info`] so access logging
    /// reads what filters actually wrote (Envoy's model — see the module
    /// doc). `Rc`, not `Arc`: this whole stream lives on one worker's
    /// `!Send` runtime (ADR-0003), so there's no cross-thread contention to
    /// pay atomic-refcount cost for.
    stream_info: Rc<RefCell<StreamInfo>>,
    /// S2.8 (ADR-0004 step 1): the route table this stream resolves against.
    /// `None` for a standalone/test invocation with no HCM route table
    /// configured (e.g. `FilterManager` driven directly in a unit test) --
    /// `route()` then always returns `None`, the same behavior this field
    /// had before route resolution existed.
    route_table: Option<Arc<RouteTable>>,
    /// S2.8: the `:authority`/`:path`/headers the NEXT unresolved `route()`
    /// call matches against. Refreshed by the decode driver from the LIVE
    /// request head immediately before every filter callback (see
    /// `sync_route_head` and its call sites in `drive_decode` /
    /// `deliver_decode_data` / `drain_decode_injections`) -- deliberately
    /// NOT computed once at the start of the whole decode chain and left
    /// alone. A decode filter may rewrite `:authority`/`:path` and then call
    /// `clear_route_cache()`; the next filter's `route()` call must resolve
    /// against what THAT filter changed it to, not the request as it arrived
    /// on the wire. That re-read is the entire point of S2.8.
    route_authority: String,
    route_path: String,
    route_headers: HeaderMap,
    /// Cached route (S2.8), populated lazily by [`resolve_and_cache_route`]
    /// (used by both [`DecoderCallbacksAdapter::route`] and, once the decode
    /// chain finishes, [`FilterManager::run`] itself before building the
    /// terminal request). `None` means either "not yet resolved" or
    /// "resolved to no match" -- both correctly retry resolution on the next
    /// call, which matters when an earlier filter's rewrite makes a route
    /// newly reachable. [`DecoderCallbacksAdapter::clear_route_cache`] resets
    /// this to `None` to force a re-resolution.
    route: Option<Arc<RouteEntry>>,
    /// ADR-0004 step 4 increment 2: this HCM's resolved `typed_per_filter_config`
    /// (see [`PerRouteTable`]). `None` for a standalone/test invocation with
    /// no table attached (e.g. most direct `FilterManager` tests) --
    /// `per_route_config()` then always returns `None`, the same shape
    /// `route_table: None` gives `route()`.
    per_route: Option<Arc<PerRouteTable>>,
    /// S2.5: a pending `send_local_reply()`, recorded here by
    /// [`DecoderCallbacksAdapter::send_local_reply`] and consumed by `run()`.
    /// First one wins — see that method's doc.
    local_reply: Option<LocalReply>,
    /// Set once `run()` hands response headers back across the seam (i.e.
    /// once [`encode_headers_phase`] has resolved). `send_local_reply` checks
    /// this to decide "synthesize a new response" vs. "too late, reset".
    response_headers_forwarded: bool,
    /// S2.5: `send_local_reply` was called after `response_headers_forwarded`
    /// was already set. We can't express a real stream reset through the body
    /// seam yet (TODO WP-11 chunk 4) — [`StreamingEncoder::poll_frame`]
    /// checks this and terminates the body with a [`crate::handler::BodyError`]
    /// instead of silently ignoring the call.
    reset_after_headers: bool,
    /// Access-log request-header snapshot (relocated from
    /// `RouterHandler::handle_and_log` — see `crate::access_logging`'s
    /// module doc): [`FilterManager::run`] writes into this at the point the
    /// task's design calls for — AFTER the decode filter chain has run, so
    /// it reflects any decode-filter header mutation, but BEFORE
    /// `apply_request_transforms`'s `request_headers_to_add` runs deep
    /// inside the router terminal for a `Forward` route, which is what
    /// actually carries dialect-injected provider credentials
    /// (`Authorization`/`x-api-key`) — an access log must never become a
    /// place those leak to. `Rc<RefCell<..>>`, not a plain field: `ChainCtx`
    /// (and so this) moves into `FilterManager`/`StreamingEncoder`/
    /// `respond_with_local_reply` and is gone by the time `run()` returns,
    /// but `FilterChainHandler::handle` needs to read this back afterward to
    /// build the `LoggingBody` it wraps the OUTERMOST response in — so it
    /// clones this `Rc` out of `ChainCtx` before `run()` ever takes
    /// ownership (see that call site), and reads it back through the clone.
    request_headers_snapshot: Rc<RefCell<Option<RequestSnapshot>>>,
}

impl ChainCtx {
    /// `stream_info` is the stream's single, shared `StreamInfo` (see the
    /// field's doc) -- passed in rather than constructed here, so the caller
    /// (`FilterChainHandler::handle`) can hand the exact same `Rc` clone to
    /// the terminal handler via `HttpRequestParts::stream_info`.
    fn new(stream_info: Rc<RefCell<StreamInfo>>) -> Self {
        Self {
            decode: DirectionState::default(),
            encode: EncodeState::default(),
            stream_info,
            route_table: None,
            route_authority: String::new(),
            route_path: String::new(),
            route_headers: HeaderMap::new(),
            route: None,
            per_route: None,
            local_reply: None,
            response_headers_forwarded: false,
            reset_after_headers: false,
            request_headers_snapshot: Rc::new(RefCell::new(None)),
        }
    }

    /// Attach the route table this stream resolves against (S2.8). A separate
    /// builder method rather than a `new` parameter, so every existing
    /// call site that doesn't exercise routing (most direct `FilterManager`
    /// tests) is unaffected -- `route()` simply keeps returning `None` for
    /// them, matching pre-S2.8 behavior.
    fn with_route_table(mut self, route_table: Arc<RouteTable>) -> Self {
        self.route_table = Some(route_table);
        self
    }

    /// Attach the resolved `typed_per_filter_config` this stream reads
    /// through `per_route_config()` (ADR-0004 step 4 increment 2). Same
    /// "separate builder, existing callers unaffected" shape as
    /// [`Self::with_route_table`].
    fn with_per_route(mut self, per_route: Arc<PerRouteTable>) -> Self {
        self.per_route = Some(per_route);
        self
    }
}

/// S2.8: refresh `ctx`'s route-resolution snapshot (`:authority`, `:path`,
/// headers) from the LIVE request head. Called immediately before every
/// decode filter callback (see the call sites in `drive_decode` /
/// `deliver_decode_data` / `drain_decode_injections`), never once at the
/// start of the whole decode chain -- see `ChainCtx::route_authority`'s doc
/// for why that distinction is the entire point of S2.8.
fn sync_route_head(ctx: &mut ChainCtx, head: &RequestHeaders) {
    let host_header = head
        .headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok());
    ctx.route_authority = head
        .uri
        .authority()
        .map(|a| a.as_str())
        .or(host_header)
        .unwrap_or("")
        .to_string();
    ctx.route_path = head
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();
    // Rust note: `HeaderMap::clone()` is a full copy, not a refcount bump --
    // acceptable here because request header maps are small (LLM proxy
    // traffic, not bulk data) and this only runs once per filter callback,
    // never per-byte.
    ctx.route_headers = head.headers.clone();
}

/// S2.8: resolve (and cache) the route against `ctx`'s current snapshot,
/// shared by [`DecoderCallbacksAdapter::route`] and by [`FilterManager::run`]
/// (so the terminal gets a result consistent with whatever a decode filter
/// already observed via `route()`/`clear_route_cache()`). Returns the cached
/// `Arc` without touching the route table when one is already cached.
fn resolve_and_cache_route(ctx: &mut ChainCtx) -> Option<Arc<RouteEntry>> {
    if let Some(route) = &ctx.route {
        return Some(route.clone());
    }
    let table = ctx.route_table.as_ref()?;
    let route_req = RouteRequest {
        authority: &ctx.route_authority,
        path: &ctx.route_path,
        headers: &ctx.route_headers,
    };
    match match_route(table, &route_req) {
        RouteMatch::Found { route, .. } => {
            let route = route.clone();
            ctx.route = Some(route.clone());
            Some(route)
        }
        // No match: cache nothing, so the very next call retries -- exactly
        // what lets a filter's rewrite (e.g. a path rewrite that makes a
        // different route reachable) be observed without an explicit
        // `clear_route_cache()` when nothing was cached in the first place.
        RouteMatch::NoRoute { .. } | RouteMatch::NoVirtualHost => None,
    }
}

/// ADR-0004 step 4 increment 2: resolve `filter_index`'s most specific
/// `typed_per_filter_config` entry for the CALLING filter's stream —
/// shared by [`DecoderCallbacksAdapter::per_route_config`] and
/// [`EncoderCallbacksAdapter::per_route_config`]. Resolving the route here
/// (via [`resolve_and_cache_route`]) is what makes this subject to the same
/// S2.8 cache and the same `clear_route_cache()` invalidation as `route()`
/// itself — see [`crate::filter::DecoderCallbacks::per_route_config`]'s doc.
fn per_route_config_for(
    ctx: &mut ChainCtx,
    filter_index: usize,
) -> Option<Arc<dyn PerRouteConfig>> {
    let route = resolve_and_cache_route(ctx)?;
    let per_route = ctx.per_route.as_ref()?;
    per_route.lookup(&route, filter_index)
}

/// S2.5: a synthesized response requested via `send_local_reply`, recorded
/// into [`ChainCtx`] until `run()` (or [`respond_with_local_reply`]) can
/// substitute it for whatever response was otherwise going to be built.
struct LocalReply {
    code: http::StatusCode,
    body: String,
    /// Rust note: [`HeaderMutationFn`] is `FnOnce` (callable exactly once,
    /// consuming it) — a field can't be *called* through `&mut self`, only
    /// moved out of. That's why every use site below takes it out of the
    /// `Option` (`Option::take`, or an `if let Some(f) = reply.modify_headers`
    /// pattern, which also moves it out) before calling it, rather than
    /// calling it in place.
    modify_headers: Option<HeaderMutationFn>,
    details: String,
}

impl LocalReply {
    /// Build a local reply carrying no header mutation — used by the
    /// manager's own synthesized failure responses (decode overflow, body
    /// read errors, encode-header-phase overflow), as opposed to one a filter
    /// requested via `send_local_reply` (which may supply `modify_headers`).
    fn new(code: http::StatusCode, body: &str, details: &str) -> Self {
        Self {
            code,
            body: body.to_string(),
            modify_headers: None,
            details: details.to_string(),
        }
    }
}

/// Sum of every position's buffered bytes for the encode direction — the
/// buffer limit is per-stream, not per-position, so overflow is checked
/// against this total (S2.7).
fn total_encode_buffered(ctx: &ChainCtx) -> usize {
    ctx.encode.positions.iter().map(|p| p.buf.0.len()).sum()
}

/// One request's worth of filter-chain execution. Consumed by [`Self::run`].
///
/// ADR-0004 step 3: `terminal` is owned (`Box<dyn TerminalHttpFilter>`), not
/// borrowed -- it's a per-stream instance minted by
/// [`crate::filter::TerminalFilterInstanceFactory`] exactly like every other
/// filter in `filters`, not a shared handler reused across requests. There is
/// no more `'t` lifetime: nothing here borrows from the caller anymore.
struct FilterManager {
    filters: Vec<Box<dyn HttpFilter>>,
    ctx: ChainCtx,
    terminal: Box<dyn TerminalHttpFilter>,
    buffer_limit: usize,
}

impl FilterManager {
    async fn run(self, req: HttpRequestParts) -> HttpResponseParts {
        let FilterManager {
            mut filters,
            mut ctx,
            mut terminal,
            buffer_limit,
        } = self;

        // Access-log request-header snapshot (fallback): taken here, before
        // `collect_request` consumes `req`, purely so the failure paths
        // right below (a request-body read error, or a decode filter's own
        // buffer overflow) -- which end before the decode chain finishes --
        // still have *something* to log with, rather than nothing at all
        // (their pre-relocation behavior: a filter-chain local reply never
        // reached `RouterHandler`, so it was never logged). Every path that
        // reaches the decode chain successfully overwrites this below with a
        // fresher, post-decode-filter snapshot — see
        // `ChainCtx::request_headers_snapshot`'s doc for why that ordering
        // matters.
        *ctx.request_headers_snapshot.borrow_mut() = Some(snapshot_request(&req.head));

        // --- collect the request body (buffered model) ---
        let (mut head, req_trailers, mut body) = match collect_request(req).await {
            Ok(parts) => parts,
            // A downstream body read error is a client problem: 400. (Streaming
            // will surface this mid-flight instead; chunk 1 sees it up front.)
            // S2.5: routed through the encoder chain like any other response —
            // no filters have run yet, but the still-fresh `filters`/`ctx` are
            // exactly what `respond_with_local_reply` needs.
            Err(()) => {
                let reply = LocalReply::new(
                    http::StatusCode::BAD_REQUEST,
                    "invalid request body",
                    "request_body_read_error",
                );
                return respond_with_local_reply(terminal, filters, ctx, buffer_limit, reply).await;
            }
        };

        // --- decode chain (config order) ---
        if let Err(status) = drive_decode(
            &mut filters,
            &mut ctx,
            buffer_limit,
            &mut head,
            &mut body,
            req_trailers.as_ref(),
        )
        .await
        {
            let reply = LocalReply::new(
                status,
                "request rejected by filter chain",
                "decode_buffer_overflow",
            );
            return respond_with_local_reply(terminal, filters, ctx, buffer_limit, reply).await;
        }

        // Access-log request-header snapshot, refreshed: the decode chain
        // has now run (see the fallback snapshot's doc above), so this
        // reflects any decode-filter header mutation -- but is still taken
        // strictly BEFORE `apply_request_transforms`'s
        // `request_headers_to_add` (deep inside the router terminal below,
        // for a `Forward` route), which is what actually carries
        // dialect-injected provider credentials. That ordering is
        // load-bearing: an access log must never become a place a
        // `Authorization`/`x-api-key` header leaks to.
        *ctx.request_headers_snapshot.borrow_mut() = Some(snapshot_request(&head));

        // S2.5: a decoder filter may have called `send_local_reply` while the
        // chain above was running. If so, the request must not reach the
        // terminal handler (the router stand-in) at all — a local reply
        // *replaces* the response, it doesn't run alongside it.
        //
        // Rust note: `ctx.local_reply.take()` both reads the value out and
        // leaves `None` in its place — needed because `ctx` itself is about
        // to move into `respond_with_local_reply` below; we can't hold a
        // borrow of it across that move.
        if let Some(reply) = ctx.local_reply.take() {
            return respond_with_local_reply(terminal, filters, ctx, buffer_limit, reply).await;
        }

        // --- terminal (ADR-0004 step 3): an ordinary filter for decode
        // purposes, minted LAST (`FilterChainHandler::handle`) and so living
        // at the very end of the decode chain -- deliver the fully-mutated
        // head/body/trailers to it exactly like `drive_decode` delivers to
        // any configured filter, then call `respond()` to produce the
        // response. Anything filters appended via `add_decoded_data` rides
        // along ahead of the original body, same as it always reached the
        // terminal.
        let mut decoded_body = join_buffer(&ctx.decode.buffer, &body);
        let end_stream_on_headers = decoded_body.is_empty() && req_trailers.is_none();
        ctx.decode.current_idx = filters.len();
        sync_route_head(&mut ctx, &head);
        {
            let mut cb = DecoderCallbacksAdapter { ctx: &mut ctx };
            let _ = terminal.decode_headers(&mut cb, &mut head, end_stream_on_headers);
        }
        if let Some(reply) = ctx.local_reply.take() {
            return respond_with_local_reply(terminal, filters, ctx, buffer_limit, reply).await;
        }

        let end_stream = req_trailers.is_none();
        {
            let mut cb = DecoderCallbacksAdapter { ctx: &mut ctx };
            let _ = terminal.decode_data(&mut cb, &mut decoded_body, end_stream);
        }
        if let Some(reply) = ctx.local_reply.take() {
            return respond_with_local_reply(terminal, filters, ctx, buffer_limit, reply).await;
        }

        if let Some(t) = &req_trailers {
            let mut owned = RequestTrailers(t.0.clone());
            {
                let mut cb = DecoderCallbacksAdapter { ctx: &mut ctx };
                let _ = terminal.decode_trailers(&mut cb, &mut owned);
            }
            if let Some(reply) = ctx.local_reply.take() {
                return respond_with_local_reply(terminal, filters, ctx, buffer_limit, reply).await;
            }
        }

        // --- terminal handler (router) produces the response ---
        let resp = {
            let mut cb = DecoderCallbacksAdapter { ctx: &mut ctx };
            terminal.respond(&mut cb).await
        };
        let HttpResponseParts { mut head, mut body } = resp;

        // --- encode header phase (async: a header hold may need to consume
        // upstream frames to resolve it, S2.2) ---
        let hold =
            match encode_headers_phase(&mut filters, &mut ctx, buffer_limit, &mut head, &mut body)
                .await
            {
                Ok(hold) => hold,
                Err(status) => {
                    // The encoder chain has ALREADY begun traversing this
                    // response — at least one filter has seen `encode_headers`.
                    // Substituting a local reply and restarting the chain from
                    // position 0 would call `encode_headers` on those filters a
                    // *second* time within one stream. That re-entrancy is
                    // precisely the bug class that hurts most here: a metering
                    // or access-logging filter would count the same response
                    // twice. Envoy draws the same line — a local reply raised
                    // once encoding is under way is sent directly rather than
                    // back through the filters.
                    //
                    // The trade-off, stated plainly: filters do NOT observe
                    // this particular 500. That is the lesser evil against
                    // double-invocation, and this path only fires when the
                    // filter chain itself blew the encode buffer limit.
                    {
                        let mut info = ctx.stream_info.borrow_mut();
                        info.is_local_reply = true;
                        info.response_code_details =
                            Some("encode_header_phase_overflow".to_string());
                    }
                    destroy_filters(terminal.as_mut(), &mut filters);
                    return synth_response(status, "response rejected by filter chain");
                }
            };

        // Response headers are about to be handed back across the seam —
        // from this point on, `send_local_reply` can no longer synthesize a
        // new response (S2.5); see `ctx.reset_after_headers`.
        ctx.response_headers_forwarded = true;

        // --- the rest of the response streams through the encoder chain on
        // demand (chunk 3): filters/ctx move into the body so callbacks keep
        // working exactly as before, just driven by `poll_frame` instead of a
        // single synchronous pass. `on_destroy` now runs in `Drop` (below),
        // since the stream — and therefore the filters' lifetime — doesn't
        // end when `run()` returns. `terminal` rides along too (S2.1: created
        // last, so destroyed first).
        let remaining_content_length = parse_content_length(&head.headers);
        let encoder = StreamingEncoder {
            terminal,
            filters,
            ctx,
            upstream: body,
            buffer_limit,
            pending: hold.pending,
            pending_trailers: hold.pending_trailers,
            upstream_done: hold.upstream_done,
            end_flush_done: false,
            flush_pos: 0,
            destroyed: false,
            remaining_content_length,
        };

        HttpResponseParts {
            head,
            body: local_boxed(encoder),
        }
    }
}

/// S2.5: substitute a synthesized response for whatever was otherwise going
/// to be sent, and drive it through the SAME encoder-chain machinery a normal
/// response uses ([`encode_headers_phase`] + [`StreamingEncoder`]) — so
/// encoder filters (token metering, access logging, ...) observe a local
/// reply exactly like any other response. Used both for an explicit
/// `send_local_reply()` call and for the failure paths `run()` itself raises.
/// Per-stream teardown (S2.1: reverse creation order).
///
/// Normally this rides on [`StreamingEncoder`]'s `Drop`, since a streaming
/// response means the filters outlive `run()`. Any path that returns a bare
/// [`synth_response`] never constructs a `StreamingEncoder`, so it must call
/// this explicitly — otherwise the filter instances are simply dropped and
/// `on_destroy` never fires. Filters that emit their stats/usage record on
/// teardown (exactly what an LLM token-metering filter does) would silently
/// report nothing for those requests. `terminal` is destroyed FIRST -- it's
/// created last (S2.1: reverse creation order), just like every other filter,
/// whether or not it ever actually ran (a local reply short-circuits before
/// the terminal's own callbacks fire, but the instance still exists and still
/// needs tearing down).
fn destroy_filters(terminal: &mut dyn TerminalHttpFilter, filters: &mut [Box<dyn HttpFilter>]) {
    terminal.on_destroy();
    for filter in filters.iter_mut().rev() {
        filter.on_destroy();
    }
}

async fn respond_with_local_reply(
    mut terminal: Box<dyn TerminalHttpFilter>,
    mut filters: Vec<Box<dyn HttpFilter>>,
    mut ctx: ChainCtx,
    buffer_limit: usize,
    reply: LocalReply,
) -> HttpResponseParts {
    // A local reply always starts the encoder chain fresh, as if this were a
    // brand-new response substituted at the very top of the chain — discard
    // any encode-side state a prior, now-abandoned attempt left behind (e.g.
    // the real response's `encode_headers_phase` partially ran before
    // overflowing and calling this function).
    ctx.encode = EncodeState::default();
    // Record onto `StreamInfo` even when this local reply came from one of
    // `run()`'s own failure paths, not a filter's `send_local_reply()` call
    // (which already records it) — every local reply must be observable this
    // way, regardless of source.
    {
        let mut info = ctx.stream_info.borrow_mut();
        info.is_local_reply = true;
        info.response_code_details = Some(reply.details.clone());
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    // Rust note: `if let Some(f) = reply.modify_headers` moves the `FnOnce`
    // out of `reply` (a plain field access can't call it in place — see
    // `LocalReply`'s doc), so it can be invoked exactly once here.
    if let Some(f) = reply.modify_headers {
        f(&mut headers);
    }
    let mut head = ResponseHeaders {
        status: reply.code,
        headers,
    };
    let mut body = bytes_to_seam_body(Bytes::from(format!("{}\n", reply.body)), None);

    match encode_headers_phase(&mut filters, &mut ctx, buffer_limit, &mut head, &mut body).await {
        Ok(hold) => {
            ctx.response_headers_forwarded = true;
            let remaining_content_length = parse_content_length(&head.headers);
            let encoder = StreamingEncoder {
                terminal,
                filters,
                ctx,
                upstream: body,
                buffer_limit,
                pending: hold.pending,
                pending_trailers: hold.pending_trailers,
                upstream_done: hold.upstream_done,
                end_flush_done: false,
                flush_pos: 0,
                destroyed: false,
                remaining_content_length,
            };
            HttpResponseParts {
                head,
                body: local_boxed(encoder),
            }
        }
        Err(status) => {
            // The local reply itself overflowed the encode buffer — there's
            // nowhere left to route it, so fall back to a bare synthesized
            // response (bypassing the chain), same as the pre-S2.5 behavior.
            // Teardown still has to happen: `on_destroy` normally rides on
            // `StreamingEncoder`'s `Drop`, and this path never builds one.
            destroy_filters(terminal.as_mut(), &mut filters);
            synth_response(status, "response rejected by filter chain")
        }
    }
}

/// What a position in the encode chain is currently doing with data it can't
/// yet forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StopKind {
    /// `StopIterationAndBuffer` / `StopIterationAndWatermark`: bytes
    /// accumulate in this position's buffer, and — this is the part the
    /// module doc calls out as easy to miss — the filter is **re-invoked with
    /// the whole accumulated buffer on every subsequent frame**, not just
    /// once at end-of-stream. That's genuine Envoy behavior (it's why the
    /// real `Buffer` filter is written as `if (end_stream) return Continue;
    /// return StopIterationAndBuffer;` — it only ever sees "continue or stay
    /// stopped" on each call, and needs to be asked again to notice
    /// end-of-stream). Without re-invoking, a buffering filter could never
    /// unstall before the stream ends.
    ///
    /// Watermark backpressure itself (applying downstream flow control
    /// instead of just accumulating) is chunk 4; here it collapses to the
    /// same "buffer and wait" behavior as the plain buffering statuses.
    Buffering,
    /// `StopIterationNoBuffer`: bytes are discarded, not replayed. The filter
    /// is NOT re-invoked (unlike `Buffering`) — only an explicit
    /// `continue_encoding()` releases it, and we have no out-of-callback
    /// waker for that yet (module doc).
    NoBuffer,
    /// `StopAllIterationAndBuffer` / `StopAllIterationAndWatermark`, from the
    /// header phase: "nothing (headers/data/trailers) proceeds past this
    /// filter" — unlike plain `StopIteration`'s S2.2 gotcha, this filter's own
    /// data callbacks do NOT fire either. Bytes just accumulate silently;
    /// nothing here re-invokes the filter (TODO WP-11 chunk 4: needs an
    /// out-of-band `continue_encoding()` to ever release, which isn't modeled
    /// yet — this position simply absorbs the rest of the stream).
    StopAll,
}

/// Per-position encode state, indexed by *position* (see
/// [`StreamingEncoder`]'s doc comment: position `p` = filter index
/// `n - 1 - p`).
///
/// # Why per-position, not one shared buffer
///
/// The chunk-3 encoder used a single `ctx.encode.buffer` plus a single
/// `stopped_at: Option<usize>` for the whole direction. That's wrong the
/// moment two positions are stopped at once (an early filter buffering while
/// a later one also buffers): the flat buffer can't tell whose bytes are
/// whose, and releasing one position would re-deliver bytes the other
/// position already saw. Fixing the "a frame must always walk from position
/// 0" bug (see the module doc) makes that double-stop reachable in practice,
/// so it has to be fixed in the same change.
///
/// # Invariant
///
/// `buf` is non-empty only where `stop.is_some()` — a *flowing* position
/// never holds bytes between calls to [`StreamingEncoder::encode_frame`].
/// That's what makes "whose bytes are these, and in what order" unambiguous:
/// anything sitting in a position's buffer is strictly earlier, in stream
/// order, than anything still arriving from upstream or from an earlier
/// position. (The invariant can be transiently violated *during* a single
/// `encode_frame` call — e.g. while a filter is being re-invoked and might
/// call `add_encoded_data` — but always holds again once the call returns.)
#[derive(Default)]
struct PositionState {
    stop: Option<StopKind>,
    /// Rust note: reusing [`BufferedBody`] (rather than a bare `BytesMut`)
    /// here — not because it needs the newtype for meaning, but because
    /// `EncoderCallbacks::encoding_buffer()` returns `Option<&BufferedBody>`
    /// and we can't manufacture that reference from a `&BytesMut`.
    buf: BufferedBody,
    /// An `end_stream = true` frame arrived while this position was stopped.
    /// Remembered so a `Buffering` re-invoke passes the real `end_stream`
    /// flag to the filter instead of always claiming `false`.
    end_pending: bool,
}

impl PositionState {
    /// Debug-only check for the invariant above; called at the start/end of
    /// [`StreamingEncoder::encode_frame`] (steady state), never mid-call.
    #[cfg(debug_assertions)]
    fn check_invariant(&self, p: usize) {
        debug_assert!(
            self.stop.is_some() || self.buf.0.is_empty(),
            "position {p} is flowing but still holds {} buffered byte(s)",
            self.buf.0.len()
        );
    }
}

/// A single upstream frame that was consumed (during a header hold, or
/// because an earlier `encode_frame` call fully buffered it) but hasn't yet
/// been delivered past `start_pos`.
struct PendingFrame {
    data: Bytes,
    end_stream: bool,
    /// Rust note: a *position* (see [`StreamingEncoder`]'s doc comment), not a
    /// filter index — this frame must resume at the filter *after* whichever
    /// one already consumed it, and positions make "next filter" a plain `+1`
    /// regardless of config order.
    start_pos: usize,
}

/// The outcome of [`encode_headers_phase`]: whatever couldn't be resolved
/// synchronously, to seed a [`StreamingEncoder`]. A stopped position (if any)
/// is recorded directly into `ctx.encode.positions` as the phase runs, rather
/// than returned separately — at most one position can come out of the header
/// phase stopped (the loop gives up at the first one it can't resolve), but
/// once real frames start flowing (chunk 3+), more than one can become
/// stopped, which is exactly why `PositionState` lives in `ctx`, not here.
struct HeaderHoldOutcome {
    pending: VecDeque<PendingFrame>,
    pending_trailers: Option<HeaderMap>,
    upstream_done: bool,
}

/// Encode header phase (S2.2 applied to the response path): walk positions
/// `0..n` (position `p` = filter index `n - 1 - p`, i.e. reverse config
/// order, S2.1) delivering `encode_headers`. Plain `StopIteration` means the
/// headers can't proceed past this filter yet — but per the S2.2 gotcha,
/// *this filter's own* data callbacks still fire while it's stopped. So we
/// pull frames off `upstream` one at a time and hand them to the held
/// filter's `encode_data` until it continues (headers then resume at `p + 1`)
/// or `upstream` ends (headers are forwarded as-is; see the TODO below).
/// `StopAllIterationAndBuffer`/`Watermark` is different: "nothing proceeds
/// past this filter" means not even this filter's own data callbacks fire —
/// there is no S2.2 gotcha for stop-all, so we don't try to resolve it here at
/// all; the position is marked `StopAll` and absorbs the rest of the stream
/// (TODO WP-11 chunk 4: only an out-of-band `continue_encoding()` should be
/// able to release it, which isn't modeled yet).
///
/// Frames consumed while resolving a `StopIteration` hold must not be lost,
/// and must not be re-delivered to filters at positions `<= p` once streaming
/// starts — they're queued into the returned `pending`, tagged with
/// `start_pos = p + 1`.
///
/// Buffer overflow here can still synthesize a 500 (`Err`), since the headers
/// have not been handed back to the caller yet.
async fn encode_headers_phase(
    filters: &mut [Box<dyn HttpFilter>],
    ctx: &mut ChainCtx,
    buffer_limit: usize,
    head: &mut ResponseHeaders,
    upstream: &mut SeamBody,
) -> Result<HeaderHoldOutcome, http::StatusCode> {
    let n = filters.len();
    // Rust note: sized here, not in `ChainCtx::new` — `n` (how many filters
    // this stream has) isn't known until the per-stream instances exist.
    ctx.encode.positions = (0..n).map(|_| PositionState::default()).collect();
    let mut pending = VecDeque::new();
    let mut upstream_done = false;
    let mut pending_trailers = None;

    let mut p = 0;
    'headers: while p < n {
        let idx = n - 1 - p;
        let status = {
            let mut cb = EncoderCallbacksAdapter { ctx, pos: p };
            // We can't know ahead of time whether the (streaming) body is
            // empty, so we never claim end_stream from the header phase; the
            // real end-of-stream flush happens once `upstream` actually ends
            // (see `StreamingEncoder::poll_frame`).
            filters[idx].encode_headers(&mut cb, head, false)
        };
        if total_encode_buffered(ctx) > buffer_limit {
            return Err(http::StatusCode::INTERNAL_SERVER_ERROR);
        }
        // S2.7: `idx` may have injected data out-of-band from `encode_headers`
        // — fold it into `pending` (entering at `p + 1`, toward the client;
        // see `StreamingEncoder`'s doc comment on position order) so it's
        // delivered once streaming starts, without re-entering `idx` itself.
        pending.extend(ctx.encode.injected.drain(..));

        match status {
            FilterHeadersStatus::Continue | FilterHeadersStatus::ContinueAndDontEndStream => {
                // ContinueAndDontEndStream: TODO(WP-11 chunk 4) requires
                // inject_*_to_filter_chain to let the filter later end the
                // stream itself; treated as Continue here.
                p += 1;
            }
            FilterHeadersStatus::StopAllIterationAndBuffer
            | FilterHeadersStatus::StopAllIterationAndWatermark => {
                ctx.encode.positions[p].stop = Some(StopKind::StopAll);
                break 'headers;
            }
            FilterHeadersStatus::StopIteration => {
                // Resolve the hold: feed upstream frames to *this* filter
                // until it continues or upstream ends.
                loop {
                    let frame = std::future::poll_fn(|cx| upstream.as_mut().poll_frame(cx)).await;
                    match frame {
                        Some(Ok(frame)) => match frame.into_data() {
                            Ok(mut data) => {
                                ctx.encode.continue_requested = false;
                                let dstatus = {
                                    let mut cb = EncoderCallbacksAdapter { ctx, pos: p };
                                    filters[idx].encode_data(&mut cb, &mut data, false)
                                };
                                if total_encode_buffered(ctx) > buffer_limit {
                                    return Err(http::StatusCode::INTERNAL_SERVER_ERROR);
                                }
                                // S2.7: same fold-in for an injection from this
                                // held filter's own `encode_data`.
                                pending.extend(ctx.encode.injected.drain(..));
                                let continued = matches!(dstatus, FilterDataStatus::Continue)
                                    || ctx.encode.continue_requested;
                                ctx.encode.continue_requested = false;
                                if continued {
                                    // Resumes at p + 1; this frame already
                                    // passed through `idx`, so it must start
                                    // downstream of it.
                                    pending.push_back(PendingFrame {
                                        data,
                                        end_stream: false,
                                        start_pos: p + 1,
                                    });
                                    p += 1;
                                    continue 'headers;
                                }
                                // Still held: the filter didn't ask us to
                                // remember this chunk (it would call
                                // `add_encoded_data` itself if it wanted
                                // that) — poll for the next frame.
                            }
                            Err(frame) => {
                                let trailers = frame
                                    .into_trailers()
                                    .expect("hyper::body::Frame is data or trailers");
                                // Trailers arrived before the hold resolved.
                                // TODO(WP-11 chunk 4): Envoy would stall/reset
                                // here rather than giving up on the hold; we
                                // forward the headers as-is and let the
                                // streaming body deliver the final
                                // end-of-stream flush to the still-held
                                // filter, same as the "upstream ends" case
                                // below.
                                pending_trailers = Some(trailers);
                                ctx.encode.positions[p].stop = Some(StopKind::Buffering);
                                upstream_done = true;
                                break 'headers;
                            }
                        },
                        Some(Err(e)) => {
                            let _ = e; // surfaced to the caller as a synth 500
                            return Err(http::StatusCode::INTERNAL_SERVER_ERROR);
                        }
                        None => {
                            // TODO(WP-11 chunk 4): Envoy would stall/reset the
                            // stream rather than force headers out with an
                            // unresolved hold; we forward as-is.
                            ctx.encode.positions[p].stop = Some(StopKind::Buffering);
                            upstream_done = true;
                            break 'headers;
                        }
                    }
                }
            }
        }
    }

    Ok(HeaderHoldOutcome {
        pending,
        pending_trailers,
        upstream_done,
    })
}

/// Parse the response's `content-length` header, if any, for
/// [`StreamingEncoder::remaining_content_length`]. `None` covers both "no
/// header" and "present but not a plain non-negative integer" (a malformed
/// header some upstream sent) — either way there's nothing to count down, so
/// the caller falls back to the ordinary post-`None` flush.
fn parse_content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(http::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

/// The response body once headers have gone out: pulls frames from
/// `upstream` on demand and runs them through the encoder chain (reverse
/// config order, S2.1) as they arrive, instead of buffering the whole
/// response first (chunk 3 — this is what makes time-to-first-token
/// possible).
///
/// # Position vs. filter index
///
/// Encode order is REVERSE config order (S2.1). Rather than tracking a
/// config index and computing "next filter" as `idx - 1` (awkward — it hits
/// zero and needs a wraparound check), everything here works in *positions*
/// `p` over `0..n`, where `filters[order(p)]` is the filter encode visits
/// p-th; `order(p) = n - 1 - p`. "Resume at the next filter" is then always
/// plain `p + 1`, regardless of which end of `filters` that corresponds to.
struct StreamingEncoder {
    /// ADR-0004 step 3: carried along purely for teardown -- `respond()` has
    /// already run by the time a `StreamingEncoder` exists, so nothing here
    /// calls into `terminal` again; `Drop` below just needs to reach it to
    /// fire `on_destroy` (S2.1: created last, destroyed first).
    terminal: Box<dyn TerminalHttpFilter>,
    filters: Vec<Box<dyn HttpFilter>>,
    ctx: ChainCtx,
    upstream: SeamBody,
    buffer_limit: usize,
    /// Frames already pulled off `upstream` (during a header hold, or
    /// because an earlier `poll_frame` call fully buffered one) but not yet
    /// delivered past their `start_pos`. Drained before touching `upstream`
    /// again, so frame order is preserved.
    pending: VecDeque<PendingFrame>,
    /// Trailers that arrived while data was still held (S2.4: trailers queue
    /// behind buffered data) — delivered once the hold clears.
    pending_trailers: Option<HeaderMap>,
    /// `upstream` has yielded its terminal `None`.
    upstream_done: bool,
    /// Whether the end-of-stream flush (an empty, `end_stream = true` frame
    /// through the chain) has already run.
    end_flush_done: bool,
    /// After the end-of-stream flush, the next position (in `0..n`) whose
    /// leftover buffer still needs flushing to the caller (TODO WP-11 chunk 4:
    /// a filter stalled forever past end-of-stream should reset the stream
    /// instead; we can't express that through the body seam yet, so we flush
    /// the bytes rather than drop them). One `poll_frame` call flushes at most
    /// one position's worth, advancing this cursor, so multiple stopped
    /// positions each get their own frame in position order.
    flush_pos: usize,
    /// Guards [`Drop::drop`] so `on_destroy` fires exactly once.
    destroyed: bool,
    /// Bytes remaining per the response's `content-length` header, decremented
    /// as each real upstream data frame is delivered (see
    /// [`Self::note_frame_len`]). `None` means either there was no
    /// `content-length` header, or the running total has already overshot it
    /// (a stale header — not ours to fix, see `note_frame_len`); either way
    /// that's a permanent fallback to the ordinary post-`None` end-of-stream
    /// flush below.
    ///
    /// # Why this exists
    ///
    /// hyper's HTTP/1 write dispatcher stops polling the response body the
    /// moment it has written exactly `content-length` bytes — the terminal
    /// `None` poll this body relies on to trigger its end-of-stream flush
    /// never happens. That's the common case for a non-streaming response
    /// (including a non-streaming LLM provider reply), so an encode filter's
    /// stream-end logic (e.g. token-usage recording) would silently never run
    /// for it.
    ///
    /// Rust note: deliberately NOT one-frame lookahead (buffer the next frame
    /// to see whether `None` follows before releasing this one) — that would
    /// add a full chunk of latency to every SSE token on the streaming path,
    /// which is the entire reason this body exists instead of just buffering
    /// the whole response. Counting down an already-known `content-length`
    /// costs nothing extra per frame and needs no buffering.
    remaining_content_length: Option<u64>,
}

impl StreamingEncoder {
    /// Assert the [`PositionState`] invariant for position `p` right after
    /// this call has finished deciding its fate for the current frame.
    ///
    /// Rust note: NOT a whole-vector scan. A position the filter chain
    /// hasn't reached yet this call may legitimately hold bytes with
    /// `stop == None` — a filter can call `add_encoded_data` from
    /// `encode_headers` (S2.7), before that position has ever seen a data
    /// frame, and those bytes wait right there (flowing, unstopped) until the
    /// position's first real frame arrives and merges them in (see the `None`
    /// arm below). So the invariant only has to hold *for a position, once
    /// its own turn this frame is over* — not globally at every instant.
    #[cfg(debug_assertions)]
    fn assert_position_ok(&self, p: usize) {
        self.ctx.encode.positions[p].check_invariant(p);
    }

    #[cfg(not(debug_assertions))]
    fn assert_position_ok(&self, _p: usize) {}

    fn over_limit(&self) -> bool {
        total_encode_buffered(&self.ctx) > self.buffer_limit
    }

    fn overflow_err(&self) -> BodyError {
        BodyError::Upstream(
            format!(
                "encode filter chain buffered more than the {}-byte limit \
                 after response headers were already forwarded; truncating the stream",
                self.buffer_limit
            )
            .into(),
        )
    }

    /// Whether any position in the encode chain is currently stopped — used
    /// to decide whether trailers must queue behind buffered data (S2.4).
    fn any_stopped(&self) -> bool {
        self.ctx.encode.positions.iter().any(|p| p.stop.is_some())
    }

    /// Count `len` bytes of a just-arrived real upstream data frame against
    /// [`Self::remaining_content_length`], and report whether THIS frame is
    /// the one that exactly exhausts it — i.e. should be treated as carrying
    /// `end_stream = true` (see this field's doc comment for why: hyper never
    /// polls again once it's written `content-length` bytes, so there is no
    /// later `None` poll to hang the end-of-stream flush off of).
    ///
    /// Falls back to `false` (and disables itself for the rest of the stream)
    /// if `len` overshoots what's left — that means a filter mutation already
    /// made the running total diverge from the header, so the header was
    /// stale before we got here; fixing a stale `content-length` is out of
    /// scope for this fix (task doc), so we just stop trying to use it.
    fn note_frame_len(&mut self, len: usize) -> bool {
        match self.remaining_content_length {
            Some(remaining) => match remaining.checked_sub(len as u64) {
                Some(0) => {
                    self.remaining_content_length = Some(0);
                    true
                }
                Some(new_remaining) => {
                    self.remaining_content_length = Some(new_remaining);
                    false
                }
                None => {
                    // Overshoot: fall back to the post-`None` flush for good.
                    self.remaining_content_length = None;
                    false
                }
            },
            None => false,
        }
    }

    /// Run one frame of data through positions `start_pos..n`. Every REAL
    /// frame (from `upstream`, or the synthetic end-of-stream flush) must
    /// call this with `start_pos = 0` — walking forward from position 0,
    /// always, is what makes every filter observe every frame regardless of
    /// what's stopped further down the chain (the defect this fixed: frames
    /// used to resume at whatever position was *last* reported stopped,
    /// silently skipping every filter before it). The only legitimate
    /// non-zero `start_pos` is [`PendingFrame::start_pos`]: a frame that was
    /// already handed to a specific filter during the header-hold's S2.2
    /// resolution loop, and must not be redelivered to that same filter.
    ///
    /// Returns the bytes that survived to the end of the chain (`None` if
    /// they were fully buffered or discarded along the way).
    ///
    /// Buffer overflow here is `Err` (not a status code): headers have
    /// already gone out, so the only thing left to do is truncate the
    /// stream with an error — there is no 500 to send anymore.
    fn encode_frame(
        &mut self,
        mut data: Bytes,
        end_stream: bool,
        start_pos: usize,
    ) -> Result<Option<Bytes>, BodyError> {
        let n = self.filters.len();
        let mut p = start_pos;
        while p < n {
            let idx = n - 1 - p;
            match self.ctx.encode.positions[p].stop {
                Some(StopKind::StopAll) => {
                    // The filter is not called at all while stop-all is in
                    // effect (unlike `Buffering` — see `StopKind`'s doc).
                    let pos = &mut self.ctx.encode.positions[p];
                    pos.buf.0.extend_from_slice(&data);
                    pos.end_pending |= end_stream;
                    if self.over_limit() {
                        return Err(self.overflow_err());
                    }
                    self.assert_position_ok(p);
                    return Ok(None);
                }
                Some(StopKind::NoBuffer) => {
                    // Bytes are discarded, not replayed (matches
                    // `StopIterationNoBuffer`'s contract); the filter is only
                    // released by an explicit `continue_encoding()`, which we
                    // have no out-of-callback waker for yet.
                    self.assert_position_ok(p);
                    return Ok(None);
                }
                Some(StopKind::Buffering) => {
                    let pos = &mut self.ctx.encode.positions[p];
                    pos.buf.0.extend_from_slice(&data);
                    pos.end_pending |= end_stream;
                    let call_end_stream = pos.end_pending;
                    // Take the whole accumulated buffer to hand to the filter
                    // as `&mut Bytes` — Envoy's actual semantics for a
                    // buffering filter: it is re-invoked with everything
                    // accumulated so far on every subsequent frame, not just
                    // once at end-of-stream (see `StopKind::Buffering`'s doc);
                    // otherwise it could never notice end-of-stream and
                    // release.
                    let mut whole = std::mem::take(&mut pos.buf).0.freeze();
                    self.ctx.encode.continue_requested = false;
                    let status = {
                        let mut cb = EncoderCallbacksAdapter {
                            ctx: &mut self.ctx,
                            pos: p,
                        };
                        self.filters[idx].encode_data(&mut cb, &mut whole, call_end_stream)
                    };
                    // S2.7: fold in anything `idx` injected out-of-band from
                    // this call — entering at `p + 1` (toward the client),
                    // never re-entering `idx`. Delivered by the next
                    // `poll_frame` iteration, which drains `self.pending`
                    // before touching `upstream` again.
                    self.pending.extend(self.ctx.encode.injected.drain(..));
                    let continued = matches!(status, FilterDataStatus::Continue)
                        || self.ctx.encode.continue_requested;
                    self.ctx.encode.continue_requested = false;
                    // Anything appended via `add_encoded_data` during the call
                    // above landed in this position's buffer (freshly emptied
                    // by the `take` above) — fold it in after the (possibly
                    // rewritten) accumulated bytes, whichever way this call
                    // resolves.
                    let trailing = std::mem::take(&mut self.ctx.encode.positions[p].buf).0;
                    if continued {
                        let pos = &mut self.ctx.encode.positions[p];
                        pos.stop = None;
                        pos.end_pending = false;
                        data = if trailing.is_empty() {
                            whole
                        } else {
                            let mut out = BytesMut::with_capacity(whole.len() + trailing.len());
                            out.extend_from_slice(&whole);
                            out.extend_from_slice(&trailing);
                            out.freeze()
                        };
                        self.assert_position_ok(p);
                        p += 1;
                        continue;
                    }
                    // Still held: leave the (possibly rewritten) accumulated
                    // bytes, plus anything newly added, in place.
                    let pos = &mut self.ctx.encode.positions[p];
                    pos.buf.0 = BytesMut::with_capacity(whole.len() + trailing.len());
                    pos.buf.0.extend_from_slice(&whole);
                    pos.buf.0.extend_from_slice(&trailing);
                    if self.over_limit() {
                        return Err(self.overflow_err());
                    }
                    self.assert_position_ok(p);
                    return Ok(None);
                }
                None => {
                    // A position with `stop == None` is "flowing," but it may
                    // still hold bytes here: a filter can call
                    // `add_encoded_data` from `encode_headers` (S2.7) before
                    // this position has ever seen a data frame. `buf_before`
                    // captures that so it can replay AHEAD of the current
                    // frame — mirroring what "buffered from before this call"
                    // meant when there was one shared per-direction buffer.
                    let buf_before = self.ctx.encode.positions[p].buf.0.len();
                    self.ctx.encode.continue_requested = false;
                    let status = {
                        let mut cb = EncoderCallbacksAdapter {
                            ctx: &mut self.ctx,
                            pos: p,
                        };
                        self.filters[idx].encode_data(&mut cb, &mut data, end_stream)
                    };
                    // S2.7: same fold-in as the `Buffering` branch above.
                    self.pending.extend(self.ctx.encode.injected.drain(..));
                    let continued = matches!(status, FilterDataStatus::Continue)
                        || self.ctx.encode.continue_requested;
                    self.ctx.encode.continue_requested = false;

                    if continued {
                        // S2.7: bytes from BEFORE this call (added via headers
                        // or an earlier resume) replay ahead of the current
                        // frame; bytes added DURING this call ride along
                        // after it.
                        if !self.ctx.encode.positions[p].buf.0.is_empty() || buf_before > 0 {
                            let mut whole = std::mem::take(&mut self.ctx.encode.positions[p].buf).0;
                            let held_before = whole.split_to(buf_before.min(whole.len()));
                            let mut out = BytesMut::with_capacity(
                                held_before.len() + data.len() + whole.len(),
                            );
                            out.extend_from_slice(&held_before);
                            out.extend_from_slice(&data);
                            out.extend_from_slice(&whole);
                            data = out.freeze();
                        }
                        self.assert_position_ok(p);
                        p += 1;
                        continue;
                    }

                    match status {
                        FilterDataStatus::StopIterationAndBuffer
                        | FilterDataStatus::StopIterationAndWatermark => {
                            let pos = &mut self.ctx.encode.positions[p];
                            pos.buf.0.extend_from_slice(&data);
                            pos.end_pending |= end_stream;
                            pos.stop = Some(StopKind::Buffering);
                        }
                        FilterDataStatus::StopIterationNoBuffer => {
                            let pos = &mut self.ctx.encode.positions[p];
                            // `NoBuffer` discards, full stop: even bytes that
                            // arrived earlier (e.g. via `add_encoded_data`
                            // from `encode_headers`) are given up here, not
                            // just the current frame's `data`.
                            pos.buf.0.clear();
                            pos.stop = Some(StopKind::NoBuffer);
                        }
                        FilterDataStatus::Continue => unreachable!("handled by `continued` above"),
                    }
                    if self.over_limit() {
                        return Err(self.overflow_err());
                    }
                    self.assert_position_ok(p);
                    return Ok(None);
                }
            }
        }
        Ok(if data.is_empty() { None } else { Some(data) })
    }

    /// S2.4: run trailers through positions `0..n` (only reachable once
    /// nothing is held — held trailers wait in `pending_trailers` instead).
    fn encode_trailers(&mut self, trailers: HeaderMap) -> HeaderMap {
        let n = self.filters.len();
        let mut owned = ResponseTrailers(trailers);
        for p in 0..n {
            let idx = n - 1 - p;
            let mut cb = EncoderCallbacksAdapter {
                ctx: &mut self.ctx,
                pos: p,
            };
            // Chunk-1-era simplification carried forward: `FilterTrailersStatus`
            // (Continue/StopIteration) isn't yet honored for encode trailers.
            let _ = self.filters[idx].encode_trailers(&mut cb, &mut owned);
        }
        owned.0
    }
}

impl Body for StreamingEncoder {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        // Rust note: every field here is `Unpin` — `Vec`, `VecDeque`,
        // `Option`, `bool`, and `upstream: Pin<Box<dyn Body>>` is
        // unconditionally `Unpin` regardless of what it points to (pinning a
        // boxed value only pins the *pointee*, and moving the `Box` itself
        // never moves that pointee). So `StreamingEncoder` as a whole is
        // `Unpin`, and `get_mut()` is sound here without any manual
        // pin-projection.
        let this = self.get_mut();

        // S2.5: `send_local_reply` was called after response headers were
        // already forwarded. TODO(WP-11 chunk 4): the correct Envoy behavior
        // is a stream RESET, which we have no primitive for through the body
        // seam yet — terminate the body with an error instead of silently
        // pretending nothing happened.
        if this.ctx.reset_after_headers {
            return Poll::Ready(Some(Err(BodyError::Upstream(
                "send_local_reply() was called after response headers were already forwarded; \
                 this should reset the stream (TODO WP-11 chunk 4), but no reset primitive \
                 exists yet, so the response is being terminated with an error instead"
                    .into(),
            ))));
        }

        loop {
            // 1. Drain anything already pulled off `upstream` first, so frame
            // order survives header holds / prior full-buffering.
            if let Some(frame) = this.pending.pop_front() {
                match this.encode_frame(frame.data, frame.end_stream, frame.start_pos) {
                    Ok(Some(bytes)) => return Poll::Ready(Some(Ok(Frame::data(bytes)))),
                    // Fully buffered — produced nothing observable; try the
                    // next queued frame (or fall through) without returning
                    // an empty data frame to the caller.
                    Ok(None) => continue,
                    Err(e) => return Poll::Ready(Some(Err(e))),
                }
            }

            if !this.upstream_done {
                match this.upstream.as_mut().poll_frame(cx) {
                    Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                        Ok(data) => {
                            // content-length flush fix: this frame may be the
                            // one hyper will never poll past (see
                            // `remaining_content_length`'s doc) — if so, run
                            // it through the chain as the end-of-stream flush
                            // itself, rather than waiting for a `None` poll
                            // that's never coming.
                            let is_final_by_length = this.note_frame_len(data.len());
                            if is_final_by_length {
                                this.end_flush_done = true;
                            }
                            // Defect fix: every real frame walks the chain
                            // from position 0, always — never resuming from
                            // wherever some *other* position last stopped,
                            // which used to skip every filter before it.
                            match this.encode_frame(data, is_final_by_length, 0) {
                                Ok(Some(bytes)) => {
                                    return Poll::Ready(Some(Ok(Frame::data(bytes))))
                                }
                                Ok(None) => continue,
                                Err(e) => return Poll::Ready(Some(Err(e))),
                            }
                        }
                        Err(frame) => {
                            let trailers = frame
                                .into_trailers()
                                .expect("hyper::body::Frame is data or trailers");
                            // S2.4: trailers queue behind any data still held.
                            if this.any_stopped() {
                                this.pending_trailers = Some(trailers);
                                continue;
                            }
                            let trailers = this.encode_trailers(trailers);
                            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
                        }
                    },
                    Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                    Poll::Ready(None) => {
                        this.upstream_done = true;
                        continue;
                    }
                    // Do NOT buffer-and-wait: returning Pending here with
                    // nothing emitted is exactly what lets bytes already
                    // produced above flush through without waiting on the
                    // rest of the upstream response.
                    Poll::Pending => return Poll::Pending,
                }
            }

            // --- upstream has ended: end-of-stream sequence ---
            if !this.end_flush_done {
                this.end_flush_done = true;
                // Deliver a final end_stream=true empty frame, from position
                // 0 (same defect-fix reasoning as above), so a filter that
                // gated on end-of-stream can release its buffer -- and so can
                // every position after it, in the same pass.
                match this.encode_frame(Bytes::new(), true, 0) {
                    Ok(Some(bytes)) => return Poll::Ready(Some(Ok(Frame::data(bytes)))),
                    Ok(None) => {} // fall through to the checks below
                    Err(e) => return Poll::Ready(Some(Err(e))),
                }
            }

            // A filter that is still stopped never continued, even on the
            // end-of-stream flush above.
            // TODO(WP-11 chunk 4): a filter that stalls past end-of-stream
            // should reset the downstream stream; we cannot express a reset
            // through the body seam yet. For now, flush whatever the manager
            // buffered so the bytes aren't silently dropped -- one position
            // per `poll_frame` call, in position order, so two positions that
            // are both still holding bytes each get their own frame rather
            // than being concatenated out of order.
            let n = this.filters.len();
            while this.flush_pos < n {
                let p = this.flush_pos;
                this.flush_pos += 1;
                if !this.ctx.encode.positions[p].buf.0.is_empty() {
                    let bytes = std::mem::take(&mut this.ctx.encode.positions[p].buf)
                        .0
                        .freeze();
                    return Poll::Ready(Some(Ok(Frame::data(bytes))));
                }
            }

            if let Some(trailers) = this.pending_trailers.take() {
                return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
            }

            return Poll::Ready(None);
        }
    }
}

impl Drop for StreamingEncoder {
    fn drop(&mut self) {
        // Rust note: `on_destroy` used to run at the end of `run()`'s
        // synchronous pass (chunk 1). Now that the response streams, the
        // filters' per-stream lifetime is the *body's* lifetime, not a single
        // function call — `Drop` is where "the stream is over" actually
        // happens, whether it ended cleanly or was dropped early (client
        // disconnect, error, etc). `destroyed` guards against firing twice if
        // something ever calls `drop` explicitly.
        if !self.destroyed {
            self.destroyed = true;
            // Reverse creation order (S2.1), same as decode's teardown --
            // `terminal` first (created last), then the configured filters.
            self.terminal.on_destroy();
            for filter in self.filters.iter_mut().rev() {
                filter.on_destroy();
            }
        }
    }
}

/// Drive the decoder chain over a fully-buffered request. Returns `Err(status)`
/// if a filter's buffering overflowed `buffer_limit` (→ 413) — the only failure
/// this chunk raises. `body` may be mutated in place by `decode_data`.
///
/// The pointer machine (S2.2/S2.3): walk filters forward delivering headers;
/// when a filter holds (`StopIteration`/buffer/stop-all), deliver the buffered
/// data to *that same* filter (S2.2: its data callbacks still fire); if it then
/// continues (returns `Continue` from `decode_data` or calls
/// `continue_decoding()`), resume header delivery at the next filter. Once the
/// header phase completes, every filter that continued on headers but has not
/// yet seen the body gets it, in config order.
///
/// A `data_consumed` guard makes each filter's `decode_data` fire **exactly
/// once**: a filter that took its data early (to resolve a header-hold) is
/// skipped by the trailing data phase.
///
/// Chunk-1 simplification (documented; the streaming chunk fixes it): a
/// held filter takes its data slightly before earlier filters in wall-clock
/// order. Since the body is a single buffered chunk, the observable
/// per-filter effect — each `decode_data` called once, in config order — is
/// preserved. A hold that never resolves synchronously (async buffering /
/// local reply) is chunk 3; here it simply stops progression past that filter.
///
/// ADR-0004 step 2: `async fn`, so a `StopIteration*` from `decode_headers` or
/// `decode_data` can now also mean "ask the filter if it has async work"
/// (`HttpFilter::poll_pending`) instead of only "wait for `continue_decoding()`".
/// See [`poll_async_resumption`] for the shared retry policy both call sites use.
async fn drive_decode(
    filters: &mut [Box<dyn HttpFilter>],
    ctx: &mut ChainCtx,
    buffer_limit: usize,
    head: &mut RequestHeaders,
    body: &mut Bytes,
    trailers: Option<&RequestTrailers>,
) -> Result<(), http::StatusCode> {
    let end_stream_on_headers = body.is_empty() && trailers.is_none();
    let mut data_consumed = vec![false; filters.len()];
    // ADR-0004 step 2: how many times each filter has been given an async
    // resumption so far, this direction — see `poll_async_resumption`'s doc
    // for the bound this enforces.
    let mut resumptions = vec![0u32; filters.len()];
    // `header_reach`: one past the last filter that received (and continued on)
    // headers. Filters `[0, header_reach)` get data in the trailing phase.
    let mut header_reach = 0;
    let mut idx = 0;
    while idx < filters.len() {
        // Split borrow: `&mut filters[idx]`, `&mut *head`, and an adapter over
        // `&mut *ctx` are three disjoint borrows (module doc).
        ctx.decode.current_idx = idx;
        // S2.8: refresh the route-resolution snapshot from the LIVE head
        // immediately before this filter runs -- see `sync_route_head`'s doc
        // for why this can't be done once, up front, for the whole chain.
        sync_route_head(ctx, head);
        let mut cb = DecoderCallbacksAdapter { ctx };
        let status = filters[idx].decode_headers(&mut cb, head, end_stream_on_headers);
        // A filter that buffered via add_decoded_data must not exceed the limit.
        if ctx.decode.buffer.0.len() > buffer_limit {
            return Err(http::StatusCode::PAYLOAD_TOO_LARGE);
        }
        // S2.7: deliver anything `idx` injected out-of-band before doing
        // anything else with its status — injected data reaches subsequent
        // filters immediately, not whenever the normal pointer machine
        // happens to get there.
        drain_decode_injections(filters, ctx, buffer_limit, head)?;

        // S2.5: once a filter has requested a local reply, decode iteration
        // stops immediately — no filter after the sender sees the request, and
        // the sender's own data callbacks don't fire either. `run()` picks up
        // the pending `ctx.local_reply` and synthesizes the response through the
        // *encoder* chain. Without this, a later filter (e.g. a metering filter
        // downstream of an auth filter that just returned 401) would still run.
        if ctx.local_reply.is_some() {
            return Ok(());
        }

        match status {
            FilterHeadersStatus::Continue | FilterHeadersStatus::ContinueAndDontEndStream => {
                // ContinueAndDontEndStream: TODO(WP-11 chunk 4) forward with
                // end_stream=false + require inject_*; treated as Continue here.
                idx += 1;
                header_reach = idx;
            }
            FilterHeadersStatus::StopIteration
            | FilterHeadersStatus::StopAllIterationAndBuffer
            | FilterHeadersStatus::StopAllIterationAndWatermark => {
                // ADR-0004 step 2: before falling back to today's "deliver the
                // buffered data to this same filter now" behavior, give the
                // filter a chance to do async work. `poll_async_resumption`
                // re-drives `decode_headers` on this SAME filter once its
                // future resolves — there is no other place in this pointer
                // machine to "resume from headers", so re-invoking the
                // callback that stopped IS the resumption (exactly as
                // `continue_decoding()` resuming it synchronously would have
                // led straight back here).
                if poll_async_resumption(filters, ctx, idx, &mut resumptions).await {
                    if ctx.local_reply.is_some() {
                        return Ok(());
                    }
                    continue; // retry decode_headers at the same idx
                }
                // Either there was no pending future (today's behavior), or
                // the resumption budget was just exhausted and `ctx.local_reply`
                // is now set — either way, fall through to the ordinary path.
                if ctx.local_reply.is_some() {
                    return Ok(());
                }
                // Headers held at `idx`. Deliver the (buffered) data to this same
                // filter; if it continues, resume header delivery at the next.
                let continued = deliver_decode_data(
                    filters,
                    ctx,
                    buffer_limit,
                    idx,
                    body,
                    trailers,
                    &mut data_consumed,
                    head,
                    &mut resumptions,
                )
                .await?;
                // S2.5: a `send_local_reply` from this filter's data/trailers
                // callback stops decode just as a header-phase one does.
                if ctx.local_reply.is_some() {
                    return Ok(());
                }
                if continued {
                    idx += 1;
                    header_reach = idx;
                } else {
                    break;
                }
            }
        }
    }

    // Trailing data phase: filters that continued on headers but haven't yet
    // seen the body, in config order.
    for i in 0..header_reach {
        if data_consumed[i] {
            continue;
        }
        deliver_decode_data(
            filters,
            ctx,
            buffer_limit,
            i,
            body,
            trailers,
            &mut data_consumed,
            head,
            &mut resumptions,
        )
        .await?;
        // S2.5: stop the trailing-data phase too if a local reply was requested.
        if ctx.local_reply.is_some() {
            return Ok(());
        }
    }
    Ok(())
}

/// ADR-0004 step 2: how many times a single filter may be given an async
/// resumption (a `Some` from `poll_pending`) for one direction of one stream.
/// A filter whose async work never lands — a bug, or a misbehaving extension
/// that always reports more pending work — must not spin the decode chain
/// forever; once a filter exceeds this many resumptions we fail closed
/// (a local reply) instead of hanging. Chosen generously: legitimate async
/// filters (e.g. `ext_authz`, WP-32) resolve in one resumption per callback
/// invocation, not a loop of their own.
const MAX_ASYNC_RESUMPTIONS_PER_FILTER: u32 = 16;

/// Ask `filters[idx]` whether it has async work pending (`HttpFilter::poll_pending`)
/// and, if so, await it. Returns `true` when the caller should retry the
/// callback that just stopped (the future resolved and the budget wasn't
/// exceeded); `false` when there was nothing pending (today's behavior:
/// fall through to the synchronous hold) OR the per-filter resumption budget
/// ([`MAX_ASYNC_RESUMPTIONS_PER_FILTER`]) was just exhausted — in the latter
/// case `ctx.local_reply` is set, and callers must check
/// `ctx.local_reply.is_some()` themselves (mirroring every other local-reply
/// check in this file) rather than relying on the `bool` alone.
///
/// Rust note: `poll_pending`'s returned future borrows only `filters[idx]`
/// (`&'a mut self` in `filter.rs`) — never `ctx` — so holding it across the
/// `.await` below only keeps `filters` mutably borrowed, not `ctx`. That's
/// exactly the split-storage discipline the module doc describes, just
/// stretched across an await point instead of a single synchronous call.
async fn poll_async_resumption(
    filters: &mut [Box<dyn HttpFilter>],
    ctx: &mut ChainCtx,
    idx: usize,
    resumptions: &mut [u32],
) -> bool {
    let Some(fut) = filters[idx].poll_pending() else {
        return false;
    };
    resumptions[idx] += 1;
    if resumptions[idx] > MAX_ASYNC_RESUMPTIONS_PER_FILTER {
        ctx.local_reply = Some(LocalReply::new(
            http::StatusCode::INTERNAL_SERVER_ERROR,
            "filter chain did not complete",
            "async_filter_resumption_limit_exceeded",
        ));
        return false;
    }
    fut.await;
    true
}

/// Deliver the buffered body (and, if the filter continues, trailers) to filter
/// `idx` exactly once. Returns whether it continued. Marks `data_consumed[idx]`.
///
/// `head` (S2.8, ADR-0004 step 1) is the one addition over the pre-S2.8
/// signature -- bundling it with the other split-storage borrows into a
/// struct isn't a clean win here (the borrows are all short-lived reborrows
/// scoped to individual calls within `drive_decode`, not one value that
/// outlives the whole function), so this just accepts the extra parameter.
///
/// ADR-0004 step 2: `async fn`, and `resumptions` (the same per-filter budget
/// `drive_decode`'s header phase uses) lets a filter that stopped on
/// `decode_data` also be offered an async resumption before this falls back
/// to "stopped, wait for `continue_decoding()`" — see [`poll_async_resumption`].
#[allow(clippy::too_many_arguments)]
async fn deliver_decode_data(
    filters: &mut [Box<dyn HttpFilter>],
    ctx: &mut ChainCtx,
    buffer_limit: usize,
    idx: usize,
    body: &mut Bytes,
    trailers: Option<&RequestTrailers>,
    data_consumed: &mut [bool],
    head: &RequestHeaders,
    resumptions: &mut [u32],
) -> Result<bool, http::StatusCode> {
    data_consumed[idx] = true;
    ctx.decode.continue_requested = false;
    ctx.decode.current_idx = idx;
    // S2.8: same refresh as `drive_decode`'s header-phase call site -- `head`
    // may have been mutated by this same filter's own (already-returned)
    // `decode_headers` call.
    sync_route_head(ctx, head);
    let end_stream = trailers.is_none();
    // ADR-0004 step 2: a `loop` because a filter may ask for (bounded) async
    // resumptions before it finally continues or gives up; every other
    // iteration is the same synchronous `decode_data` call chunk 1 always made.
    loop {
        let mut cb = DecoderCallbacksAdapter { ctx };
        let status = filters[idx].decode_data(&mut cb, body, end_stream);
        if ctx.decode.buffer.0.len() > buffer_limit {
            return Err(http::StatusCode::PAYLOAD_TOO_LARGE);
        }
        // S2.7: `idx` may have injected data out-of-band from `decode_data` —
        // deliver it to filters after `idx` before deciding anything else.
        drain_decode_injections(filters, ctx, buffer_limit, head)?;
        let continued =
            matches!(status, FilterDataStatus::Continue) || ctx.decode.continue_requested;

        if continued {
            if let Some(t) = trailers {
                ctx.decode.current_idx = idx;
                sync_route_head(ctx, head);
                let mut cb = DecoderCallbacksAdapter { ctx };
                let mut owned = RequestTrailers(t.0.clone());
                let _ = filters[idx].decode_trailers(&mut cb, &mut owned);
                // S2.7: same for an injection from `decode_trailers`.
                drain_decode_injections(filters, ctx, buffer_limit, head)?;
            }
            return Ok(true);
        }

        // Not continued: offer this filter an async resumption before
        // falling back to "stopped" (today's behavior).
        if poll_async_resumption(filters, ctx, idx, resumptions).await {
            if ctx.local_reply.is_some() {
                return Ok(false);
            }
            // Retry `decode_data` at the same `idx` — same policy as the
            // header phase: re-invoking the callback that stopped is the
            // resumption.
            ctx.decode.continue_requested = false;
            continue;
        }
        // `poll_async_resumption` may have set `ctx.local_reply` itself
        // (resumption budget exhausted); either way the caller's own
        // `ctx.local_reply.is_some()` check right after this call handles it.
        return Ok(false);
    }
}

/// S2.7: deliver every out-of-band injection queued in `ctx.decode.injected`
/// (via `inject_decoded_data_to_filter_chain`) to the filters strictly AFTER
/// its originator, in order — never re-entering the originator, and never
/// touching `continue_requested` (so injecting never itself resumes the
/// originator's own held iteration).
///
/// Decode has no streaming driver (module doc: decode stays fully buffered),
/// so a downstream filter that itself stops on an injected chunk has no later
/// point to resume it at — same documented limitation the header-hold
/// resolution loop above already accepts for a hold that never resolves
/// synchronously. Anything that makes it past every subsequent filter rides
/// along to the terminal exactly like `add_decoded_data` (appended to the
/// shared decode buffer that `join_buffer` prepends to the body).
///
/// Rust note: `while let Some(..) = ctx.decode.injected.pop_front()` (not a
/// single drain-into-a-`Vec` pass) — delivering one injected chunk can itself
/// call `inject_decoded_data_to_filter_chain` again, pushing more work onto
/// the very queue we're draining; popping one at a time picks that up.
fn drain_decode_injections(
    filters: &mut [Box<dyn HttpFilter>],
    ctx: &mut ChainCtx,
    buffer_limit: usize,
    head: &RequestHeaders,
) -> Result<(), http::StatusCode> {
    while let Some((from_idx, mut data, end_stream)) = ctx.decode.injected.pop_front() {
        let n = filters.len();
        let mut idx = from_idx + 1;
        while idx < n {
            ctx.decode.current_idx = idx;
            ctx.decode.continue_requested = false;
            // S2.8: same refresh as elsewhere -- an injected chunk's
            // recipient can call `route()` too.
            sync_route_head(ctx, head);
            let mut cb = DecoderCallbacksAdapter { ctx };
            let status = filters[idx].decode_data(&mut cb, &mut data, end_stream);
            if ctx.decode.buffer.0.len() > buffer_limit {
                return Err(http::StatusCode::PAYLOAD_TOO_LARGE);
            }
            let continued =
                matches!(status, FilterDataStatus::Continue) || ctx.decode.continue_requested;
            ctx.decode.continue_requested = false;
            if !continued {
                break;
            }
            idx += 1;
        }
        if idx == n {
            ctx.decode.buffer.0.extend_from_slice(&data);
        }
    }
    Ok(())
}

// --- callback adapters -----------------------------------------------------

/// Borrows only [`ChainCtx`]; never the filter list (module doc).
struct DecoderCallbacksAdapter<'c> {
    ctx: &'c mut ChainCtx,
}

impl DecoderCallbacks for DecoderCallbacksAdapter<'_> {
    fn send_local_reply(
        &mut self,
        code: http::StatusCode,
        body: &str,
        modify_headers: Option<HeaderMutationFn>,
        details: &str,
    ) {
        {
            let mut info = self.ctx.stream_info.borrow_mut();
            info.is_local_reply = true;
            info.response_code_details = Some(details.to_string());
        }

        if self.ctx.response_headers_forwarded {
            // S2.5: once response headers have already gone out, a NEW
            // response can't be sent — Envoy resets the stream instead. We
            // have no reset primitive through the body seam yet
            // (TODO(WP-11 chunk 4): plumb a real stream reset), so the best
            // we can do without silently ignoring the call is terminate the
            // response body with an error; `StreamingEncoder::poll_frame`
            // checks this flag and surfaces it.
            self.ctx.reset_after_headers = true;
            return;
        }

        if self.ctx.local_reply.is_some() {
            // First one wins — matches Envoy, which also ignores a second
            // `sendLocalReply()` while one is already pending. A filter that
            // calls this twice is a filter bug, not something we can recover
            // from more gracefully here.
            return;
        }

        self.ctx.local_reply = Some(LocalReply {
            code,
            body: body.to_string(),
            modify_headers,
            details: details.to_string(),
        });
    }

    fn continue_decoding(&mut self) {
        self.ctx.decode.continue_requested = true;
    }

    fn add_decoded_data(&mut self, data: Bytes, _streaming: bool) {
        self.ctx.decode.buffer.0.extend_from_slice(&data);
    }

    fn inject_decoded_data_to_filter_chain(&mut self, data: Bytes, end_stream: bool) {
        // S2.7: out-of-band — delivered to the filters strictly AFTER the one
        // currently running (`ctx.decode.current_idx`, stashed by the driver
        // right before this callback's owning call), never re-entering it.
        // Recorded here; the driver (`drain_decode_injections`) delivers it
        // immediately after this callback returns.
        self.ctx
            .decode
            .injected
            .push_back((self.ctx.decode.current_idx, data, end_stream));
    }

    fn decoding_buffer(&self) -> Option<&BufferedBody> {
        if self.ctx.decode.buffer.0.is_empty() {
            None
        } else {
            Some(&self.ctx.decode.buffer)
        }
    }

    fn modify_decoding_buffer(&mut self, f: &mut dyn FnMut(&mut BytesMut)) {
        f(&mut self.ctx.decode.buffer.0);
    }

    fn route(&mut self) -> Option<Arc<RouteEntry>> {
        // S2.8: resolve lazily, against whatever `sync_route_head` most
        // recently refreshed `self.ctx` with (i.e. the request as of THIS
        // callback), and cache it -- shared with `FilterManager::run`'s own
        // pre-terminal resolution so both see the same answer.
        resolve_and_cache_route(self.ctx)
    }

    fn clear_route_cache(&mut self) {
        self.ctx.route = None;
    }

    fn per_route_config(&mut self) -> Option<Arc<dyn PerRouteConfig>> {
        // `current_idx` is the filter index the driver is calling right now
        // (module doc on `DirectionState::current_idx`) -- exactly the
        // "calling filter, never another's" isolation this method promises.
        let filter_index = self.ctx.decode.current_idx;
        per_route_config_for(self.ctx, filter_index)
    }

    fn stream_info(&mut self) -> std::cell::RefMut<'_, StreamInfo> {
        self.ctx.stream_info.borrow_mut()
    }
}

/// Encoder mirror of [`DecoderCallbacksAdapter`]. Unlike decode, encode
/// buffers per-*position*, not per-direction (module doc), so this also
/// carries which position is calling back right now — `encoding_buffer()` /
/// `modify_encoding_buffer()` / `add_encoded_data()` all operate on THIS
/// position's slot in `ctx.encode.positions`.
///
/// Rust note: `BufferedBody` (in `filter.rs`) and the `EncoderCallbacks` trait
/// signatures are frozen; the position is threaded through here, in the
/// adapter, rather than by changing either of those.
struct EncoderCallbacksAdapter<'c> {
    ctx: &'c mut ChainCtx,
    pos: usize,
}

impl EncoderCallbacks for EncoderCallbacksAdapter<'_> {
    fn continue_encoding(&mut self) {
        self.ctx.encode.continue_requested = true;
    }

    fn add_encoded_data(&mut self, data: Bytes, _streaming: bool) {
        self.ctx.encode.positions[self.pos]
            .buf
            .0
            .extend_from_slice(&data);
    }

    fn inject_encoded_data_to_filter_chain(&mut self, data: Bytes, end_stream: bool) {
        // S2.7: out-of-band — delivered to the filter AFTER this position
        // (`pos + 1`, i.e. toward the client; see `StreamingEncoder`'s doc
        // comment on position order), never re-entering this one. Reuses
        // `PendingFrame`'s shape: the driver (`encode_headers_phase` /
        // `StreamingEncoder::encode_frame`) folds this into whichever
        // `pending` queue is in scope right after this callback returns,
        // which honors `pos + 1`'s (and everything after it's) existing
        // `StopKind`/buffer state exactly like a header-hold's leftover frame
        // does.
        self.ctx.encode.injected.push_back(PendingFrame {
            data,
            end_stream,
            start_pos: self.pos + 1,
        });
    }

    fn encoding_buffer(&self) -> Option<&BufferedBody> {
        let buf = &self.ctx.encode.positions[self.pos].buf;
        if buf.0.is_empty() {
            None
        } else {
            Some(buf)
        }
    }

    fn modify_encoding_buffer(&mut self, f: &mut dyn FnMut(&mut BytesMut)) {
        f(&mut self.ctx.encode.positions[self.pos].buf.0);
    }

    fn per_route_config(&mut self) -> Option<Arc<dyn PerRouteConfig>> {
        // Position `p` = filter index `n - 1 - p` (module doc, "Position vs.
        // filter index") -- `ctx.encode.positions` is sized to `n` by
        // `encode_headers_phase` before any encode callback runs, so this is
        // always in range once a callback is actually calling back.
        let n = self.ctx.encode.positions.len();
        let filter_index = n.checked_sub(1 + self.pos)?;
        per_route_config_for(self.ctx, filter_index)
    }

    fn stream_info(&mut self) -> std::cell::RefMut<'_, StreamInfo> {
        self.ctx.stream_info.borrow_mut()
    }
}

// --- body plumbing ---------------------------------------------------------

/// Collect a request into head + optional trailers + buffered body bytes.
async fn collect_request(
    req: HttpRequestParts,
) -> Result<(RequestHeaders, Option<RequestTrailers>, Bytes), ()> {
    // `downstream` is only used by `FilterChainHandler::handle` (XFF/S9,
    // access-log peer address), all of which runs before `FilterManager::run`
    // is even called -- this function only needs head + body.
    let HttpRequestParts {
        head,
        body,
        downstream: _,
    } = req;
    let collected = body.collect().await.map_err(|_| ())?;
    let trailers = collected.trailers().cloned().map(RequestTrailers);
    Ok((head, trailers, collected.to_bytes()))
}

/// Prepend a filter-manager buffer (bytes added via `add_*_data`) to the
/// original body. In the common case the buffer is empty and this is just a
/// clone of `body`.
fn join_buffer(buffer: &BufferedBody, body: &Bytes) -> Bytes {
    if buffer.0.is_empty() {
        body.clone()
    } else {
        let mut out = BytesMut::with_capacity(buffer.0.len() + body.len());
        out.extend_from_slice(&buffer.0);
        out.extend_from_slice(body);
        out.freeze()
    }
}

/// Build a [`SeamBody`] carrying `bytes` as a single data frame plus optional
/// trailers — faithfully preserving trailers across the seam.
fn bytes_to_seam_body(bytes: Bytes, trailers: Option<HeaderMap>) -> SeamBody {
    use hyper::body::Frame;
    let mut frames: Vec<Result<Frame<Bytes>, BodyError>> = Vec::new();
    if !bytes.is_empty() {
        frames.push(Ok(Frame::data(bytes)));
    }
    if let Some(t) = trailers {
        frames.push(Ok(Frame::trailers(t)));
    }
    local_boxed(StreamBody::new(futures::stream::iter(frames)))
}

/// A minimal synthesized response that bypasses the encoder chain entirely.
/// Only used as the last-resort fallback when a local reply (S2.5) itself
/// can't be routed through the chain — e.g. it overflows the encode buffer
/// limit in [`respond_with_local_reply`]. Every other failure path now goes
/// through the chain via [`LocalReply`] / [`respond_with_local_reply`].
fn synth_response(status: http::StatusCode, message: &str) -> HttpResponseParts {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    let body = format!("{message}\n");
    HttpResponseParts {
        head: ResponseHeaders { status, headers },
        body: bytes_to_seam_body(Bytes::from(body), None),
    }
}

#[cfg(test)]
mod streaming_tests;
#[cfg(test)]
mod tests;
