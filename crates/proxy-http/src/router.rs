//! WP-13 v1 (thin slice): the router terminal filter. Since ADR-0004 step 3
//! this is an ordinary [`crate::filter::HttpFilter`] that also implements
//! [`crate::filter::TerminalHttpFilter`] -- `proxy-core`'s HTTP connection
//! manager wiring plugs a [`RouterFilterFactory`] in as the LAST entry of the
//! filter chain (mirroring Envoy's `envoy.filters.http.router`, which is
//! simply the terminal `StreamDecoderFilter`) -- matches a route (`crate::route`), picks a cluster + host through
//! `proxy_cluster::manager::ClusterManager`, dials/reuses an upstream
//! connection, and proxies the request over it with
//! [`crate::codec::send_upstream_http1`].
//!
//! ## v1 scope
//!
//! In scope: `Forward` routing to a `Cluster`/`ClusterHeader`/`Weighted`
//! target, both HTTP/1.1 and HTTP/2 upstreams. HTTP/1.1 is connect-per-stream
//! (no pooling/reuse -- see `proxy_cluster::pool`); HTTP/2 reuses one
//! connection per (cluster, address) across concurrent/sequential requests
//! via `crate::upstream_pool::UpstreamConnCache` (WP-15 slice A -- see that
//! module's doc). `DirectResponse` for inline bodies, the
//! upstream request transforms `prefix_rewrite`/`host_rewrite_literal`/
//! `x-envoy-expected-rq-timeout-ms`, the S4 route timeout
//! (`ForwardAction::timeout`, bounding time-to-response-headers only), and
//! the S4 route `idle_timeout` (`ForwardAction::idle_timeout`), applied to
//! the **response** (server->client) body only -- once headers arrive, a
//! gap of more than `idle_timeout` between response body frames resets the
//! stream (`router::idle::IdleTimeoutBody`) rather than hanging forever, the
//! LLM-relevant direction for a stalled token stream. See `apply_forward`
//! below for how the two timeouts compose.
//!
//! Also in scope: the S5 `max_requests` circuit breaker
//! (`ClusterEntry::circuit_breaker(RoutingPriority::Default)`), acquired
//! before dialing and held for the whole response stream via
//! `router::guarded::GuardedBody` -- exceeding it sheds load as `UO` + 503 +
//! `x-envoy-overloaded` rather than piling onto a struggling upstream. The
//! other three S5 budgets (`max_connections`, `max_pending_requests`,
//! `max_retries`) have real counters in `proxy_cluster::CircuitBreakerState`
//! but no call site yet -- see the `TODO`s there.
//!
//! Deferred (known feature gaps, not silent drops -- ground rule #1):
//! - S9 request-header transforms: XFF, `x-request-id`, `:authority`
//!   rewrite. `crate::headers` already implements the functions; this
//!   router doesn't call them yet.
//! - Request-direction body idle (bounding gaps in the *downstream* request
//!   body) and HCM-level `stream_idle_timeout` inheritance -- the IR has no
//!   HCM `stream_idle_timeout` field yet, so a `None` route `idle_timeout`
//!   means "no idle timeout" for now, not "inherit the listener's".
//! - The retry & hedging engine (S3, WP-14).
//! - HTTP/1.1 connection reuse (keep-alive) -- WP-15 slice B; h1 stays
//!   connect-per-stream through `ConnectPool` even after slice A, which only
//!   covers HTTP/2 (see `crate::upstream_pool`'s module doc for why).
//! - Connection-level circuit breakers (`max_connections`,
//!   `max_pending_requests`) -- WP-15 slice D; this router still only
//!   enforces the S5 `max_requests` per-cluster budget above.
//! - `RouteActionIR::Redirect` (returns 501 below).
//!
//! WP-24 chunk 3: response flags are recorded onto a per-request
//! [`StreamInfo`] (not just `tracing::debug!`'d) at every site below --
//! `%BYTES_RECEIVED%`, upstream host/cluster/protocol, response flags. This
//! router no longer renders access-log lines itself: that moved up to
//! [`crate::filter_manager::FilterChainHandler`] (see its module doc and
//! [`crate::access_logging`]'s doc for why -- in short, this router sits
//! INSIDE the encode filter chain, so logging from here can never observe
//! what an encode filter does at end-of-stream).

use std::rc::Rc;
use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode};
use http_body_util::{BodyExt, Full};
use proxy_cluster::manager::ClusterManager;
use proxy_cluster::{
    ClusterEntry, LoadBalancerContext, PoolError, RoutingPriority, UpstreamProtocol, UpstreamStream,
};
use proxy_config::ir::{DataSourceIR, ForwardTarget, RouteActionIR, RouteMatcher};
use proxy_observability::ResponseFlag;

use crate::codec::{send_upstream_http1, Http1Options, UpstreamCodecError};
use crate::filter::{
    DecoderCallbacks, FilterDataStatus, FilterHeadersStatus, FilterTrailersStatus, HttpFilter,
    RequestHeaders, RequestTrailers, ResponseHeaders, TerminalFilterInstanceFactory,
    TerminalHttpFilter,
};
use crate::handler::{
    local_boxed, DownstreamInfo, HttpRequestParts, HttpResponseParts, StreamBody,
};
use crate::retry::{AttemptOutcome, RetryState};
use crate::route::{apply_prefix_rewrite, select_cluster};
use crate::stat_handles::RouterStats;
use crate::upstream_pool::{ConnKey, PooledSendRequest, UpstreamConnCache};
use guarded::GuardedBody;
use idle::IdleTimeoutBody;

/// What `apply_forward`'s attempt loop got back from connecting to the
/// picked host: an h1 [`UpstreamStream`] for a fresh connect-per-stream dial,
/// or a [`PooledSendRequest`] leased from the worker's bounded h2 connection
/// set -- possibly a clone of an already-cached, already-handshaken sender,
/// possibly a freshly dialed one (WP-15 slice A, extended to a bounded set
/// of connections by slice C -- see `crate::upstream_pool`'s module doc).
/// One `Result<Connected, PoolError>` for both protocols keeps the shared
/// connect-failure handling (S3 retry classification, circuit-breaker
/// outcome, response-flag mapping) a single match arm instead of two
/// near-duplicate ones.
enum Connected {
    Http1(UpstreamStream),
    Http2(PooledSendRequest),
}

mod guarded;
// Rust note: `pub(crate)` (not private) so `access_logging::LoggingBody`, a
// sibling of `router` rather than a child, can name `idle::IdleTimeoutError`
// to distinguish "upstream went quiet" (SI) from "upstream connection died"
// (UC) when classifying a body error for the access log.
pub(crate) mod idle;

/// S3.4 (Envoy's `no_retry_body_too_large`): the largest request body this
/// router will hold in memory for retry replay. Matches
/// `filter_manager::DEFAULT_BUFFER_LIMIT` -- both exist for the same reason
/// (the decode chain is already fully buffered by the time a request reaches
/// the router terminal, so this doesn't add a *new* buffering cost, just caps
/// how much of what's already buffered upstream we're willing to hold a
/// second (replayable) copy of).
const RETRY_REQUEST_BUFFER_LIMIT: usize = 1 << 20;

/// ADR-0004 step 3: the router's own [`TerminalFilterInstanceFactory`] --
/// mints a fresh [`RouterHandler`] per stream, exactly like every other
/// filter's factory. `Send + Sync` (required by `TerminalFilterInstanceFactory`,
/// see its doc) because it only holds `Arc`s -- thread-safe config-time
/// state, same shape as `FilterInstanceFactory` implementors.
///
/// WP-23 increment 6a: `stats` is built once per worker (a fresh
/// [`RouterStats`] carrying that worker's own `WorkerId` -- see
/// `crates/proxy/src/main.rs`'s `worker_main`) and handed in here alongside
/// `clusters`, the same way every other piece of shared, worker-scoped state
/// reaches the router: through the factory that `proxy-core`'s listener
/// wiring builds once per (worker, config version), not through anything
/// resolved per request.
pub struct RouterFilterFactory {
    clusters: Arc<ClusterManager>,
    stats: Arc<RouterStats>,
}

impl RouterFilterFactory {
    pub fn new(clusters: Arc<ClusterManager>, stats: Arc<RouterStats>) -> Self {
        Self { clusters, stats }
    }
}

impl TerminalFilterInstanceFactory for RouterFilterFactory {
    fn create_terminal_filter(&self) -> Box<dyn TerminalHttpFilter> {
        Box::new(RouterHandler::new(
            self.clusters.clone(),
            self.stats.clone(),
        ))
    }
}

/// The router terminal: matches a route, then forwards to the picked
/// cluster/host over a real upstream connection. See the module doc for v1
/// scope.
///
/// ADR-0004 step 3: this is now an ordinary [`HttpFilter`] instance, created
/// fresh per stream (S2.1) -- it no longer resolves routes privately or holds
/// a `route_table` of its own; it reads the filter manager's cached route via
/// `DecoderCallbacks::route()` (S2.8), exactly like any other filter would.
/// `decode_headers`/`decode_data`/`decode_trailers` below capture the fully
/// -mutated request the same way any filter captures state from its own
/// callbacks -- there is no more bespoke `HttpRequestParts` field carrying it
/// across a seam.
pub struct RouterHandler {
    clusters: Arc<ClusterManager>,
    /// WP-23 increment 6a: this worker's `upstream_rq`/`upstream_rq_time`
    /// recorder -- see `apply_forward`'s attempt loop for where it's called
    /// and why.
    stats: Arc<RouterStats>,
    /// WP-15 slice A: this worker's h2 connection-reuse cache. `Rc`, not a
    /// field on `RouterFilterFactory` -- see `upstream_pool::worker_conn_cache`'s
    /// doc for why the factory (which must stay `Send + Sync`) can't hold
    /// this directly, and why a `thread_local!` is the fallback instead.
    /// Fetched fresh per stream (a cheap `Rc` clone -- pointer bump), so
    /// every request this worker serves shares the one underlying cache.
    conn_cache: Rc<UpstreamConnCache>,
    /// Captured in `decode_headers` (cloned, since `RequestHeaders` isn't
    /// `Clone` and the callback only lends us `&mut`); consumed by
    /// `respond()`.
    captured_head: Option<RequestHeaders>,
    /// Captured in `decode_data`. Decode is fully buffered before any filter
    /// runs (`filter_manager`'s module doc), so this one call always carries
    /// the whole request body -- there's nothing incremental to accumulate.
    captured_body: Bytes,
    /// Captured in `decode_trailers`, when present.
    captured_trailers: Option<RequestTrailers>,
}

impl RouterHandler {
    pub fn new(clusters: Arc<ClusterManager>, stats: Arc<RouterStats>) -> Self {
        Self {
            clusters,
            stats,
            conn_cache: crate::upstream_pool::worker_conn_cache(),
            captured_head: None,
            captured_body: Bytes::new(),
            captured_trailers: None,
        }
    }
}

impl HttpFilter for RouterHandler {
    fn decode_headers(
        &mut self,
        _cb: &mut dyn DecoderCallbacks,
        headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        self.captured_head = Some(RequestHeaders {
            method: headers.method.clone(),
            uri: headers.uri.clone(),
            headers: headers.headers.clone(),
        });
        FilterHeadersStatus::Continue
    }

    fn decode_data(
        &mut self,
        _cb: &mut dyn DecoderCallbacks,
        data: &mut Bytes,
        _end_stream: bool,
    ) -> FilterDataStatus {
        self.captured_body = data.clone();
        FilterDataStatus::Continue
    }

    fn decode_trailers(
        &mut self,
        _cb: &mut dyn DecoderCallbacks,
        trailers: &mut RequestTrailers,
    ) -> FilterTrailersStatus {
        self.captured_trailers = Some(RequestTrailers(trailers.0.clone()));
        FilterTrailersStatus::Continue
    }
}

impl TerminalHttpFilter for RouterHandler {
    // Rust note: boxed/pinned future, same shape every other `HttpFilter`/
    // `TerminalHttpFilter` method that needs to be async uses (object safety
    // -- `async fn` in a trait isn't callable through a trait object).
    fn respond<'a>(
        &'a mut self,
        cb: &'a mut dyn DecoderCallbacks,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HttpResponseParts> + 'a>> {
        Box::pin(async move { self.route_and_forward(cb).await })
    }
}

impl RouterHandler {
    async fn route_and_forward(&mut self, dcb: &mut dyn DecoderCallbacks) -> HttpResponseParts {
        // S2.8: the filter manager already resolved (and cached) the route
        // by the time the decode chain reaches the terminal -- read it
        // through the same callback every other filter would use. There is
        // no more private fallback resolution (ADR-0004 step 3): the router
        // always runs inside a filter chain that owns a route table.
        let route = dcb.route();

        let head = self.captured_head.take().unwrap_or_else(|| {
            tracing::error!(
                "RouterHandler::respond called with no captured request head -- \
                 decode_headers never ran; this indicates a filter-manager bug"
            );
            RequestHeaders {
                method: http::Method::GET,
                uri: http::Uri::from_static("/"),
                headers: HeaderMap::new(),
            }
        });

        match route {
            None => {
                tracing::debug!(response_flag = "NR", "no route matched");
                dcb.stream_info()
                    .set_response_flag(ResponseFlag::NoRouteFound);
                local_reply(StatusCode::NOT_FOUND, "no route matched")
            }
            Some(route) => match &route.action {
                RouteActionIR::Forward(fwd) => {
                    self.apply_forward(
                        fwd,
                        &route.matcher,
                        &route.request_headers_to_add,
                        head,
                        dcb,
                    )
                    .await
                }
                RouteActionIR::DirectResponse { status, body } => {
                    direct_response(*status, body.as_ref())
                }
                RouteActionIR::Redirect(_) => {
                    tracing::debug!(
                        "TODO(WP-13 follow-up: redirects) -- redirect action not yet implemented"
                    );
                    local_reply(
                        StatusCode::NOT_IMPLEMENTED,
                        "redirect actions are not yet implemented",
                    )
                }
            },
        }
    }

    async fn apply_forward(
        &self,
        fwd: &proxy_config::ir::ForwardAction,
        matcher: &RouteMatcher,
        request_headers_to_add: &[proxy_config::ir::HeaderMutation],
        head: RequestHeaders,
        dcb: &mut dyn DecoderCallbacks,
    ) -> HttpResponseParts {
        let draw = match &fwd.target {
            ForwardTarget::Weighted(w) if w.total_weight > 0 => {
                rand::random::<u64>() % w.total_weight
            }
            _ => 0,
        };

        let Some(cluster_name) = select_cluster(&fwd.target, &head.headers, draw) else {
            tracing::debug!(
                response_flag = "NC",
                "forward target resolved to no cluster"
            );
            dcb.stream_info()
                .set_response_flag(ResponseFlag::NoClusterFound);
            return local_reply(StatusCode::SERVICE_UNAVAILABLE, "no cluster");
        };
        // Rust note: `select_cluster` borrows `cluster_name` from
        // `head.headers` (the `ClusterHeader` case) or from `fwd.target`
        // (a `'static`-ish `String` living in the route table) -- either way
        // it's tied to `head`/`self`'s lifetime, so it has to be copied out
        // (`to_string`) before `head` is mutated below.
        let cluster_name = cluster_name.to_string();

        let Some(entry) = self.clusters.cluster(&cluster_name) else {
            tracing::debug!(response_flag = "NC", cluster = %cluster_name, "unknown cluster");
            dcb.stream_info()
                .set_response_flag(ResponseFlag::NoClusterFound);
            return local_reply(StatusCode::SERVICE_UNAVAILABLE, "unknown cluster");
        };

        let mut head = head;
        apply_request_transforms(fwd, matcher, request_headers_to_add, &mut head);

        // ADR-0004 step 3: the whole request body is already captured
        // (`self.captured_body`) by the time `respond()` runs -- decode is
        // fully buffered before any filter (including the terminal) sees the
        // request (`filter_manager`'s module doc), so there is no more
        // "streamed straight through vs. collected up front" distinction to
        // make here: every attempt (retried or not) just clones the same,
        // already-in-memory `Bytes` (a refcount bump, never a deep copy).
        // WP-24: `%BYTES_RECEIVED%` is exact and known up front for the same
        // reason.
        let body_bytes = self.captured_body.clone();
        dcb.stream_info().bytes_received = body_bytes.len() as u64;
        let trailers = self.captured_trailers.as_ref().map(|t| t.0.clone());

        let mut retry_state = fwd.retry_policy.as_ref().map(RetryState::new);
        if let Some(state) = &mut retry_state {
            if body_bytes.len() > RETRY_REQUEST_BUFFER_LIMIT {
                // S3.4 (Envoy's `no_retry_body_too_large`): too big to
                // safely hold a second copy of for replay. The request still
                // proceeds -- it just can't be retried.
                state.mark_body_not_retriable();
            }
        }

        // S4: `fwd.timeout`, when set, is an *overall* budget across every
        // attempt (Envoy's route `timeout` is not a per-try timeout -- the IR
        // has no per-try timeout field, see `RetryPolicyIR::per_try_timeout`'s
        // doc), so it wraps the whole attempt loop below rather than a single
        // `send`. With no retry policy the loop runs exactly once, so this is
        // unobservable from a no-retry route's point of view.
        //
        // WP-35: built once, outside the loop (not fresh per attempt like
        // `attempt_head` below), because `attempted_clusters` has to
        // accumulate *across* attempts -- an aggregate's second attempt
        // needs to see the first attempt's pick to skip it. `mut` because
        // the loop pushes onto it after every pick.
        let mut ctx = LoadBalancerContext::default();

        // Rust note: this `async` block (no `move`) captures `dcb` (a `&mut
        // dyn DecoderCallbacks`) by unique reborrow, not by value -- so once
        // this future is dropped (whether by completing or by the outer
        // `fwd.timeout` racing it against a timer), the reborrow ends and
        // `dcb` is usable again in the code below.
        let attempt_loop = async {
            loop {
                // S5: acquire a `max_requests` permit for this attempt before
                // doing any more work for it. Requests are priority `Default`
                // for now -- per-priority route selection is a later WP.
                // Rust note: scoped to one loop iteration, so `continue`
                // (a retry) drops it and the next attempt acquires fresh --
                // exactly what "an attempt is free to land on a different
                // host" implies for its circuit-breaker accounting too.
                //
                // WP-35: deliberately still `entry` (the *routed* cluster),
                // not the not-yet-known `attempt_entry` a few lines below --
                // this matches Envoy, whose `Router::Filter` checks the
                // routed cluster's `max_requests` before any host selection
                // even runs, not the eventually-dialed host's cluster.
                // Concretely: today an aggregate's members all share the
                // aggregate's own `max_requests` budget (there is no
                // per-member budget to acquire instead -- S5's other three
                // budgets are connection-pool-level, WP-15, and likewise
                // untouched by which member ends up dialed).
                let cb = entry.circuit_breaker(RoutingPriority::Default);
                let Some(rq_guard) = cb.try_acquire_request() else {
                    tracing::debug!(response_flag = "UO", cluster = %cluster_name, "circuit breaker: max_requests exceeded");
                    dcb.stream_info()
                        .set_response_flag(ResponseFlag::UpstreamOverflow);
                    let mut resp =
                        local_reply(StatusCode::SERVICE_UNAVAILABLE, "upstream overloaded");
                    resp.head
                        .headers
                        .insert("x-envoy-overloaded", HeaderValue::from_static("true"));
                    return resp;
                };

                let Some(sel) = entry.select_host(&ctx) else {
                    tracing::debug!(response_flag = "UH", cluster = %cluster_name, "no healthy upstream host");
                    dcb.stream_info()
                        .set_response_flag(ResponseFlag::NoHealthyUpstream);
                    return local_reply(StatusCode::SERVICE_UNAVAILABLE, "no healthy upstream");
                };
                let host = sel.host;
                // WP-35: `entry` is the *routed* cluster (a plain cluster,
                // or an aggregate); `sel.member` is set only when `entry` is
                // an aggregate and names the member that actually owns
                // `host`. Everything from here on -- protocol, pool,
                // credentials, `%UPSTREAM_CLUSTER%` -- has to come from
                // whichever cluster owns the host, never from `entry`
                // itself, or an aggregate's members would share the
                // aggregate's (empty) credentials instead of their own.
                //
                // Rust note: `attempt_entry` reborrows either
                // `sel.member`'s `Arc<dyn ClusterEntry>` (`.as_ref()`) or
                // the outer `entry: Arc<dyn ClusterEntry>` (`.as_ref()`) --
                // both produce the same `&dyn ClusterEntry` type, so the
                // rest of the loop body doesn't need to know which case
                // it's in.
                let (attempt_cluster, attempt_entry): (&str, &dyn ClusterEntry) = match &sel.member
                {
                    Some(m) => (m.name.as_str(), m.entry.as_ref()),
                    None => (cluster_name.as_str(), entry.as_ref()),
                };
                // Record this attempt's cluster so a retry that falls back
                // to an aggregate skips it on the next pick (see
                // `LoadBalancerContext::attempted_clusters`'s doc). A plain
                // `String` clone, not a borrow, so it doesn't conflict with
                // `attempt_cluster` still being read below.
                ctx.attempted_clusters.push(attempt_cluster.to_string());

                // WP-23 increment 6a: this is "the attempt is actually
                // dispatched" -- past the S5 circuit breaker and host
                // selection above, so this is exactly one increment per
                // upstream attempt (a retry is a second, later iteration of
                // this same loop, so it increments again), against the
                // cluster this attempt is actually sent to (`attempt_cluster`
                // -- the member on a failover, never the routed aggregate
                // `cluster_name`). A circuit-breaker rejection returns before
                // this point and so never increments at all, matching
                // Envoy's own `upstream_rq_total` (a `max_requests` rejection
                // shows up as `upstream_rq_pending_overflow`/
                // `upstream_rq_overflow`, not as a request issued to the
                // cluster). `attempt_dispatched_at` is this same attempt's
                // clock start for `upstream_rq_time` below -- every exit from
                // this iteration past this point (`continue` or `return`)
                // pairs with exactly one `record_attempt_duration_ms`/
                // `record_attempt_duration_since` call, so the two
                // instruments stay in lockstep per attempt.
                self.stats.record_attempt(attempt_cluster);
                let attempt_dispatched_at = std::time::Instant::now();

                let proto = attempt_entry.upstream_protocol();
                // WP-24: both known right here, at the dial site -- recorded
                // onto `StreamInfo` for `%UPSTREAM_HOST%`/`%UPSTREAM_CLUSTER%`/
                // `%PROTOCOL%` before the connect is even attempted, so a
                // failed attempt still logs which host/cluster/protocol it
                // was aimed at (matching Envoy's own access-log behavior on
                // an upstream failure). A later retry attempt overwrites
                // these with its own host, which is what makes the *last*
                // attempt's target the one that ends up logged. `%UPSTREAM_CLUSTER%`
                // names `attempt_cluster` (the cluster actually dialed), not
                // the routed `cluster_name` -- matching Envoy's own
                // `upstream_host->cluster().name()`.
                {
                    let mut info = dcb.stream_info();
                    info.upstream_cluster = Some(attempt_cluster.to_string());
                    info.upstream_host = Some(host.address.to_string());
                    info.protocol = Some(
                        match proto {
                            UpstreamProtocol::Http1 => "HTTP/1.1",
                            UpstreamProtocol::Http2 => "HTTP/2",
                        }
                        .to_string(),
                    );
                }
                let pool = attempt_entry.http_pool(&host, proto);
                // WP-15 slice A: h2 upstreams are reused across requests via
                // this worker's `UpstreamConnCache` -- one TCP connection
                // (and handshake) per (cluster, address, protocol),
                // multiplexed by hyper's h2 `SendRequest`. h1 stays
                // connect-per-stream (`pool.new_stream()` directly),
                // unchanged from before this slice -- see
                // `crate::upstream_pool`'s module doc for why h2 only.
                let conn_key = matches!(proto, UpstreamProtocol::Http2)
                    .then(|| ConnKey::new(attempt_cluster, host.address, proto));
                let connect_result: Result<Connected, PoolError> = match &conn_key {
                    Some(key) => self
                        .conn_cache
                        .get_or_connect(key.clone(), pool.as_ref())
                        .await
                        .map(Connected::Http2),
                    None => pool.new_stream().await.map(Connected::Http1),
                };
                let connected = match connect_result {
                    Ok(connected) => connected,
                    Err(err) => {
                        self.stats
                            .record_attempt_duration_since(attempt_cluster, attempt_dispatched_at);
                        let outcome = AttemptOutcome::from_pool_error(&err);
                        if let Some(state) = &mut retry_state {
                            if state.should_retry(&outcome) {
                                sleep_backoff_and_record(state).await;
                                continue;
                            }
                        }
                        // Rust note: bound to `resp` (rather than `return
                        // match err {...}` directly) so the WP-24 `URX` flag
                        // below can be recorded AFTER this arm's own flag --
                        // `render_flags` joins in recording order, and Envoy
                        // always shows the specific failure first (e.g.
                        // `UF,URX`), never the other way around.
                        let resp = match err {
                            PoolError::Overflow => {
                                tracing::debug!(response_flag = "UO", cluster = %attempt_cluster, "pool overflow");
                                dcb.stream_info()
                                    .set_response_flag(ResponseFlag::UpstreamOverflow);
                                let mut resp = local_reply(
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    "upstream overloaded",
                                );
                                resp.head
                                    .headers
                                    .insert("x-envoy-overloaded", HeaderValue::from_static("true"));
                                resp
                            }
                            PoolError::ConnectFailure(_) | PoolError::ConnectTimeout => {
                                tracing::debug!(response_flag = "UF", cluster = %attempt_cluster, "upstream connect failure");
                                dcb.stream_info()
                                    .set_response_flag(ResponseFlag::UpstreamConnectionFailure);
                                local_reply(
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    "upstream connect failure",
                                )
                            }
                            // The TCP connect succeeded but the transport
                            // socket's handshake (TLS: bad certificate, no
                            // shared ALPN, version mismatch...) didn't --
                            // Envoy folds this into the same `UF`/
                            // connect-failure bucket as a TCP failure, but it
                            // gets its own arm so the log line says which
                            // half actually broke. WP-15 slice A: an h2
                            // preface/settings handshake failure (through
                            // `UpstreamConnCache::get_or_connect`) is folded
                            // into this same variant too -- see that
                            // function's doc for why.
                            PoolError::TlsHandshake(_) => {
                                tracing::debug!(response_flag = "UF", cluster = %attempt_cluster, "upstream TLS handshake failure");
                                dcb.stream_info()
                                    .set_response_flag(ResponseFlag::UpstreamConnectionFailure);
                                local_reply(
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    "upstream connect failure",
                                )
                            }
                            PoolError::ResetBeforeHeaders => {
                                tracing::debug!(response_flag = "UR", cluster = %attempt_cluster, "upstream reset before headers");
                                dcb.stream_info()
                                    .set_response_flag(ResponseFlag::UpstreamRemoteReset);
                                local_reply(StatusCode::SERVICE_UNAVAILABLE, "upstream reset")
                            }
                        };
                        record_retry_limit_exceeded_if_applicable(&retry_state, &outcome, dcb);
                        return resp;
                    }
                };

                // Rust note: a fresh `RequestHeaders` for this attempt --
                // `head` itself stays owned by the outer scope for the *next*
                // attempt, so this clones the (small) method/uri/header-map
                // trio rather than moving `head` away after one use.
                let mut attempt_head = RequestHeaders {
                    method: head.method.clone(),
                    uri: head.uri.clone(),
                    headers: head.headers.clone(),
                };
                // WP-35: apply the *cluster's* header mutations here, inside
                // the retry loop, to this attempt's own head -- never
                // hoisted up next to `apply_request_transforms` above, which
                // only sees the route. `attempt_entry` is the cluster this
                // attempt actually dialed -- the routed `entry` itself for a
                // plain cluster, or the resolved member for an aggregate --
                // so a later attempt that falls back to a different provider
                // gets that provider's credentials, never a previous
                // attempt's. This is what keeps a provider credential from
                // following the routing decision instead of the connection
                // (see `ClusterConfig::request_headers_to_add`'s doc, and
                // `ClusterKind::Aggregate`'s for why the member -- not the
                // aggregate, which carries none -- is what has to supply
                // this). Applied after the route-level mutations above, so a
                // cluster-level value wins on a key collision.
                apply_header_mutations(
                    attempt_entry.request_headers_to_add(),
                    &mut attempt_head.headers,
                );
                // Rust note: `body_bytes` is plain `Bytes`, cheap
                // (refcounted) to `.clone()` fresh for every attempt --
                // there's no separate "streaming" body anymore (see this
                // function's body-handling doc above).
                let attempt_body: StreamBody =
                    body_with_trailers(body_bytes.clone(), trailers.clone());

                let upstream_req = HttpRequestParts {
                    head: attempt_head,
                    body: attempt_body,
                    downstream: DownstreamInfo::loopback(),
                };

                // Dispatch on the cluster's configured upstream protocol.
                // Both codecs yield the same
                // `Result<HttpResponseParts, UpstreamCodecError>`; box the
                // future so the two arms share one type. h2 here is
                // prior-knowledge cleartext (h2c) over the pool's raw TCP
                // stream -- no per-request `Connection: close`, so it takes
                // no `Http1Options`. WP-15 slice A/C: the h2 arm sends over
                // whatever connection `connected` was leased from -- possibly
                // a clone of an already-cached, already-handshaken sender,
                // not a fresh one this attempt just dialed --
                // `PooledSendRequest::send` (not `codec::send_on_http2`
                // directly) so the stream stays counted as in-flight against
                // that connection for the whole response, not just until
                // headers arrive.
                let send: std::pin::Pin<
                    Box<
                        dyn std::future::Future<
                            Output = Result<HttpResponseParts, UpstreamCodecError>,
                        >,
                    >,
                > = match connected {
                    Connected::Http1(upstream) => Box::pin(send_upstream_http1(
                        upstream.io,
                        upstream_req,
                        Http1Options { keep_alive: false },
                    )),
                    Connected::Http2(pooled) => Box::pin(pooled.send(upstream_req)),
                };

                // S4.2: a route with a retry policy may additionally set
                // `per_try_timeout`, a *single attempt's* budget -- distinct
                // from `fwd.timeout`'s whole-loop budget wrapped around
                // `attempt_loop` below. It's armed fresh every time this
                // point in the loop is reached (a fresh `tokio::time::timeout`
                // call per iteration, not one timer reused across attempts),
                // which is what makes attempt N+1 get its own full
                // `per_try_timeout` rather than inheriting however much of it
                // attempt N already burned.
                //
                // Rust note: `tokio::time::timeout` races `send` against a
                // timer and returns `Err(Elapsed)` on expiry -- exactly like
                // the outer `fwd.timeout` wrap below, but scoped to just this
                // attempt. On expiry the `send` future here is dropped
                // (never polled again), which drops the upstream `TcpStream`
                // it owns and so resets/closes that one attempt's connection
                // -- the *next* attempt (if a retry follows) dials a fresh
                // one via `pool.new_stream()` at the top of the loop, it
                // never reuses a timed-out connection.
                let per_try_timeout = fwd
                    .retry_policy
                    .as_ref()
                    .and_then(|policy| policy.per_try_timeout);
                let attempt_result = match per_try_timeout {
                    Some(d) => match tokio::time::timeout(d, send).await {
                        Ok(result) => result,
                        Err(_elapsed) => {
                            self.stats.record_attempt_duration_since(
                                attempt_cluster,
                                attempt_dispatched_at,
                            );
                            let outcome = AttemptOutcome::PerTryTimeout;
                            if let Some(state) = &mut retry_state {
                                if state.should_retry(&outcome) {
                                    sleep_backoff_and_record(state).await;
                                    continue;
                                }
                            }
                            tracing::debug!(
                                response_flag = "UT",
                                cluster = %attempt_cluster,
                                timeout_ms = d.as_millis(),
                                "upstream per-try timeout waiting for response headers"
                            );
                            dcb.stream_info()
                                .set_response_flag(ResponseFlag::UpstreamRequestTimeout);
                            record_retry_limit_exceeded_if_applicable(&retry_state, &outcome, dcb);
                            return local_reply(
                                StatusCode::GATEWAY_TIMEOUT,
                                "upstream request timeout",
                            );
                        }
                    },
                    None => send.await,
                };

                match attempt_result {
                    Ok(mut resp) => {
                        self.stats
                            .record_attempt_duration_since(attempt_cluster, attempt_dispatched_at);
                        let outcome = AttemptOutcome::Response(resp.head.status.as_u16());
                        let retriable = retry_state
                            .as_ref()
                            .is_some_and(|state| state.should_retry(&outcome));
                        if retriable {
                            // Drain the failed attempt's response body before
                            // retrying so its connection isn't left dangling
                            // mid-read.
                            let _ = resp.body.collect().await;
                            let state = retry_state.as_mut().expect("checked Some above");
                            sleep_backoff_and_record(state).await;
                            continue;
                        }
                        // WP-24: this is the one `URX` site that isn't
                        // paired with a synthesized `local_reply` -- `resp`
                        // is the real (failing) upstream response, passed
                        // through unmodified; the only flag it can carry at
                        // all is this one.
                        record_retry_limit_exceeded_if_applicable(&retry_state, &outcome, dcb);
                        // Rust note: the route `timeout` bounds the whole
                        // attempt loop, not just this last attempt's
                        // `send` -- once headers arrive here the timeout is
                        // fully out of the picture: the *body* stream
                        // returned below has no further deadline (S4 -- this
                        // is what makes LLM-streaming routes safe to bound
                        // this way).
                        if let Some(idle) = fwd.idle_timeout {
                            resp.body = local_boxed(IdleTimeoutBody::new(resp.body, idle));
                        }
                        // S5: wrap outermost (after any idle_timeout wrap) so
                        // the `max_requests` permit is held until the very
                        // last response frame is produced or the body is
                        // dropped, whichever comes first -- not just until
                        // headers arrive.
                        resp.body = local_boxed(GuardedBody::new(resp.body, rq_guard));
                        return resp;
                    }
                    Err(err) => {
                        self.stats
                            .record_attempt_duration_since(attempt_cluster, attempt_dispatched_at);
                        // WP-15 slice A, hazard 2: a send failure on a cached
                        // h2 sender means it's suspect (e.g. the peer closed
                        // right as we sent) -- evict it so the next
                        // request/retry redials rather than risking the same
                        // now-dead sender again before its `is_closed()`
                        // catches up.
                        if let Some(key) = &conn_key {
                            self.conn_cache.invalidate(key);
                        }
                        let outcome = AttemptOutcome::from_codec_error(&err);
                        if let Some(state) = &mut retry_state {
                            if state.should_retry(&outcome) {
                                sleep_backoff_and_record(state).await;
                                continue;
                            }
                        }
                        // A refused stream is a REMOTE RESET, not a codec
                        // failure -- the peer deliberately bounced the
                        // stream, which is exactly what Envoy's `UR` means.
                        // Every other codec error stays `UC`. Before the
                        // refused-stream decode landed, `UR` was declared and
                        // never produced by anything (docs/envoy-divergences.md
                        // recorded it as dead code); this is its first real
                        // producer.
                        if matches!(err, UpstreamCodecError::RefusedStream) {
                            tracing::debug!(response_flag = "UR", cluster = %attempt_cluster, "upstream refused the stream");
                            dcb.stream_info()
                                .set_response_flag(ResponseFlag::UpstreamRemoteReset);
                        } else {
                            tracing::debug!(response_flag = "UC", cluster = %attempt_cluster, "upstream codec error");
                            dcb.stream_info()
                                .set_response_flag(ResponseFlag::UpstreamConnectionTermination);
                        }
                        record_retry_limit_exceeded_if_applicable(&retry_state, &outcome, dcb);
                        return local_reply(StatusCode::BAD_GATEWAY, "upstream connection failure");
                    }
                }
            }
        };

        // Rust note: the `let outcome = ...;` binding here (rather than
        // matching directly on `tokio::time::timeout(..).await`/
        // `attempt_loop.await` and using `dcb` again inside an arm of that
        // same `match`) matters: a temporary produced in a `match`'s
        // scrutinee lives until the end of the WHOLE match statement, and
        // that temporary is still holding `attempt_loop`'s reborrow of `dcb`.
        // Ending the statement here (the temporary's scope ends at this
        // `;`) releases that reborrow before `dcb` is used again below.
        let outcome = match fwd.timeout {
            Some(d) => tokio::time::timeout(d, attempt_loop).await,
            None => Ok(attempt_loop.await),
        };
        match outcome {
            Ok(resp) => resp,
            Err(_elapsed) => {
                tracing::debug!(
                    response_flag = "UT",
                    cluster = %cluster_name,
                    timeout_ms = fwd.timeout.map(|d| d.as_millis()),
                    "upstream request timed out waiting for response headers"
                );
                dcb.stream_info()
                    .set_response_flag(ResponseFlag::UpstreamRequestTimeout);
                local_reply(StatusCode::GATEWAY_TIMEOUT, "upstream request timeout")
            }
        }
    }
}

/// Sleep this attempt's S3.3 backoff delay, then record it against the
/// retry budget -- in that order, matching `RetryState::backoff_delay`'s doc
/// (the 1-based attempt number it computes is the same whether read right
/// before or right after `record_attempt`).
///
/// Rust note: `rand::random` is reached for directly here (rather than
/// threading a `rand::Rng` through) since this is the one real (not
/// deterministically-tested) call site -- `retry.rs`'s own tests inject a
/// fixed closure instead.
async fn sleep_backoff_and_record(state: &mut RetryState<'_>) {
    let delay = state.backoff_delay(&mut rand::random::<f64>);
    tokio::time::sleep(delay).await;
    state.record_attempt();
}

/// WP-24: the one call site for `ResponseFlag::UpstreamRetryLimitExceeded`
/// (`URX`) -- see [`RetryState::retry_limit_exceeded`]'s doc for exactly
/// which failures qualify. Called from every attempt-loop exit that already
/// decided not to retry `outcome`, right after that exit's OWN flag (if any)
/// is set, so a combined line renders `<flag>,URX` -- matching Envoy, which
/// never puts `URX` first. A no-op when this route has no retry policy at
/// all (`retry_state` is `None`): there is no budget for anything to exceed.
fn record_retry_limit_exceeded_if_applicable(
    retry_state: &Option<RetryState<'_>>,
    outcome: &AttemptOutcome,
    dcb: &mut dyn DecoderCallbacks,
) {
    if let Some(state) = retry_state {
        if state.retry_limit_exceeded(outcome) {
            dcb.stream_info()
                .set_response_flag(ResponseFlag::UpstreamRetryLimitExceeded);
        }
    }
}

/// Build a fresh, single-use [`StreamBody`] from already-buffered bytes (and,
/// if the captured request carried any, trailers) -- used both to build each
/// attempt's upstream request body (retried or not, ADR-0004 step 3: the
/// whole body is always already in memory by the time the terminal runs) and
/// by [`local_reply_with_status`] for a synthesized reply.
///
/// Bug found (and fixed here) while wiring ADR-0004 step 3, not caused by it:
/// the no-trailers case must use `Full`, not `http_body_util::StreamBody`
/// wrapping a `futures::stream::iter` -- `StreamBody` never overrides
/// `Body::size_hint()`, so hyper's client can't see an exact length and falls
/// back to `Transfer-Encoding: chunked` even though the whole (buffered)
/// payload is already known up front. `Full` DOES report an exact
/// `size_hint()`, which is what lets hyper send a plain `Content-Length`
/// request instead -- exactly what this function's two HEAD-era predecessors
/// (`body_from_bytes` using `Full`, a separate trailers-only path) did before
/// being merged into one function here. `router_retry.rs`'s
/// `the_replayed_request_carries_the_same_body_as_the_original` is what
/// caught the regression: its upstream test double parses the wire bytes
/// against a `Content-Length` header and got the raw chunked framing instead.
fn body_with_trailers(bytes: Bytes, trailers: Option<HeaderMap>) -> StreamBody {
    use hyper::body::Frame;
    match trailers {
        None => local_boxed(
            Full::new(bytes).map_err(|infallible: std::convert::Infallible| match infallible {}),
        ),
        Some(t) => {
            let mut frames: Vec<Result<Frame<Bytes>, crate::handler::BodyError>> = Vec::new();
            if !bytes.is_empty() {
                frames.push(Ok(Frame::data(bytes)));
            }
            frames.push(Ok(Frame::trailers(t)));
            local_boxed(http_body_util::StreamBody::new(futures::stream::iter(
                frames,
            )))
        }
    }
}

/// Apply the S13/S4 upstream request transforms to the outgoing request
/// head, in place, before it's handed to `send_upstream_http1`:
/// `prefix_rewrite` (rewrites `head.uri`), `host_rewrite_literal` (rewrites
/// the `Host` header, which is what carries `:authority` over h1), the
/// `x-envoy-expected-rq-timeout-ms` header Envoy sets from the route's S4
/// timeout so the upstream knows its deadline, and finally the route's
/// `request_headers_to_add` mutations (e.g. provider credentials injected by
/// the simple dialect).
///
/// Ordering: `request_headers_to_add` is applied *last*, after the rewrites
/// above -- this mirrors Envoy's router `finalizeRequestHeaders`, which
/// performs host/path rewrite first and then runs the route's header
/// mutations, so a mutation that happens to target `host` (or any other
/// rewrite-adjacent header) is the final word, not the rewrite.
fn apply_request_transforms(
    fwd: &proxy_config::ir::ForwardAction,
    matcher: &RouteMatcher,
    request_headers_to_add: &[proxy_config::ir::HeaderMutation],
    head: &mut crate::filter::RequestHeaders,
) {
    if let Some(rewrite) = &fwd.prefix_rewrite {
        let current_path = head.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        match apply_prefix_rewrite(matcher, rewrite, current_path) {
            Some(new_path) => match http::Uri::builder().path_and_query(new_path).build() {
                Ok(uri) => head.uri = uri,
                Err(err) => {
                    tracing::warn!(error = %err, "prefix_rewrite produced an invalid URI, leaving path unchanged");
                }
            },
            None => {
                tracing::debug!(
                    "prefix_rewrite configured but the matched route's matcher didn't yield a rewritten path"
                );
            }
        }
    }

    if let Some(host) = &fwd.host_rewrite_literal {
        match HeaderValue::from_str(host) {
            Ok(value) => {
                head.headers.insert(http::header::HOST, value);
            }
            Err(err) => {
                tracing::warn!(error = %err, host, "host_rewrite_literal is not a valid header value, skipping");
            }
        }
    }

    if let Some(d) = fwd.timeout {
        if let Ok(value) = HeaderValue::from_str(&d.as_millis().to_string()) {
            head.headers.insert("x-envoy-expected-rq-timeout-ms", value);
        }
    }

    apply_header_mutations(request_headers_to_add, &mut head.headers);
}

/// Apply a route's `request_headers_to_add` mutations, in config order, to
/// the outgoing request headers -- this is what actually gets a
/// dialect-injected provider credential (`Authorization`/`x-api-key`/
/// `anthropic-version`/...) onto the wire; see the P0 this fixes in
/// `router.rs`'s module doc history.
///
/// Rust note: `http::HeaderName` always lower-cases on construction (it's
/// case-insensitive by spec), so parsing `mutation.key` into one and then
/// using `HeaderMap`'s `contains_key`/`get`/`insert`/`append` (all of which
/// key off the canonical `HeaderName`) gives case-insensitive matching for
/// free -- no `.to_ascii_lowercase()` needed anywhere here.
fn apply_header_mutations(
    mutations: &[proxy_config::ir::HeaderMutation],
    headers: &mut http::HeaderMap,
) {
    use proxy_config::ir::HeaderAppendAction;

    for mutation in mutations {
        let Ok(name) = http::HeaderName::from_bytes(mutation.key.as_bytes()) else {
            tracing::warn!(key = %mutation.key, "request_headers_to_add: invalid header name, skipping");
            continue;
        };
        let Ok(value) = HeaderValue::from_str(&mutation.value) else {
            tracing::warn!(key = %mutation.key, "request_headers_to_add: invalid header value, skipping");
            continue;
        };

        match mutation.action {
            // Keep any existing value(s) and add this as an additional
            // instance -- `HeaderMap::append` (unlike `insert`) never
            // displaces what's already there.
            HeaderAppendAction::AppendIfExistsOrAdd => {
                headers.append(name, value);
            }
            // Only insert when nothing with this name is present yet; a
            // client-supplied value (e.g. a client-forged `Authorization`)
            // must not be able to displace it, but this action also must not
            // clobber an existing one -- this is the security-relevant case
            // from the task: it is NOT the same as `OverwriteIfExistsOrAdd`.
            HeaderAppendAction::AddIfAbsent => {
                if !headers.contains_key(&name) {
                    headers.insert(name, value);
                }
            }
            // Replace any existing value(s), or insert if absent.
            // `HeaderMap::insert` already drops every prior value for this
            // name and installs exactly one.
            HeaderAppendAction::OverwriteIfExistsOrAdd => {
                headers.insert(name, value);
            }
            // Replace only if already present; never insert.
            HeaderAppendAction::OverwriteIfExists => {
                if headers.contains_key(&name) {
                    headers.insert(name, value);
                }
            }
        }
    }
}

/// Synthesize a `DirectResponse` action's reply. `DataSourceIR::Inline` is
/// the only body variant handled for v1; a `File` body is non-trivial
/// (loading + caching file contents isn't wired anywhere in this WP) so it
/// gets a logged 500 rather than a silent empty body (ground rule #1).
fn direct_response(status: u16, body: Option<&DataSourceIR>) -> HttpResponseParts {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    match body {
        None => local_reply_with_status(status, Bytes::new()),
        Some(DataSourceIR::Inline(text)) => {
            local_reply_with_status(status, Bytes::from(text.clone()))
        }
        Some(DataSourceIR::File(path)) => {
            tracing::warn!(
                path = %path.display(),
                "TODO(WP-13 follow-up): direct_response file-sourced body not yet implemented"
            );
            local_reply(
                StatusCode::INTERNAL_SERVER_ERROR,
                "direct_response file body not yet implemented",
            )
        }
    }
}

/// A locally-synthesized error reply (no upstream involved) with a
/// plain-text body -- mirrors `stub::FixedResponseHandler`'s body
/// construction.
fn local_reply(status: StatusCode, msg: &str) -> HttpResponseParts {
    local_reply_with_status(status, Bytes::copy_from_slice(msg.as_bytes()))
}

fn local_reply_with_status(status: StatusCode, body: Bytes) -> HttpResponseParts {
    let body: StreamBody = local_boxed(
        Full::new(body).map_err(|infallible: std::convert::Infallible| match infallible {}),
    );
    HttpResponseParts {
        head: ResponseHeaders {
            status,
            headers: http::HeaderMap::new(),
        },
        body,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::net::SocketAddr;
    use std::time::Duration;

    use http::{HeaderMap, Method, StatusCode, Uri};
    use proxy_cluster::manager::ClusterManager;
    use proxy_cluster::resolver::FakeResolver;
    use proxy_config::ir::{
        CircuitBreakerThresholds, CircuitBreakers, ClusterConfig, ClusterKind, ClusterName,
        DiscoveryType, EndpointIR, ForwardAction, ForwardTarget, LbPolicy, PathMatch, RouteEntry,
        RouteMatcher, RouteTable, VirtualHostIR,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio::task::LocalSet;

    use super::*;
    use crate::filter::{FilterInstanceFactory, RequestHeaders};
    use crate::filter_manager::FilterChainHandler;
    use crate::handler::{DownstreamInfo, StreamHandler};
    use crate::stat_handles::StatHandles;
    use proxy_observability::stats::{StatsControl, WorkerId};

    /// WP-23 increment 6a: a fresh, single-worker [`RouterStats`] resolved
    /// for exactly `cluster_names` -- what every `build_router*` helper below
    /// hands to [`RouterFilterFactory::new`], mirroring how
    /// `crates/proxy/src/main.rs` builds the real one from the boot config
    /// snapshot's cluster names.
    fn test_router_stats(cluster_names: &[&str]) -> Arc<RouterStats> {
        let control = StatsControl::new(1);
        let handles = Arc::new(StatHandles::build(&control, cluster_names.iter().copied()));
        Arc::new(RouterStats::new(control.registry(), handles, WorkerId(0)))
    }

    /// A one-shot "reflecting" upstream: accepts a single connection, reads
    /// until the request's header terminator (`\r\n\r\n`), hands the raw
    /// request-line+headers text back over `rx`, then answers 200 -- this is
    /// what lets the tests assert on what actually reached the wire, not on
    /// the router's internal state.
    async fn spawn_reflecting_upstream() -> (SocketAddr, oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let n = stream.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let request_text = String::from_utf8_lossy(&buf).to_string();
            let _ = tx.send(request_text);
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
        });
        (addr, rx)
    }

    /// An upstream that accepts the connection, drains whatever the router
    /// sent, and then never responds -- used to prove the S4 route timeout
    /// actually fires rather than the router hanging forever.
    async fn spawn_hanging_upstream() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            // Rust note: `std::future::pending` never resolves -- this task
            // just holds the accepted connection open forever (until the
            // test's runtime shuts down and drops it), so the router's own
            // timeout is what has to end the request, not the peer.
            std::future::pending::<()>().await;
        });
        addr
    }

    /// An upstream that answers with chunked headers, writes one body
    /// chunk, then stalls forever (never sends the terminating `0\r\n\r\n`
    /// chunk nor closes the connection) -- used to prove the response
    /// `idle_timeout` fires on the *body*, after headers have already
    /// arrived (unlike `spawn_hanging_upstream`, which stalls before
    /// headers).
    async fn spawn_upstream_that_stalls_mid_body() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")
                .await
                .unwrap();
            // Rust note: same shape as `spawn_hanging_upstream`'s
            // `std::future::pending` -- hold the connection open forever
            // without writing the closing `0\r\n\r\n` chunk, so only the
            // router's own idle timeout can end the response body.
            std::future::pending::<()>().await;
        });
        addr
    }

    /// An upstream that streams `frame_count` chunked body frames, each
    /// separated by `gap` (kept under the route's idle timeout), then closes
    /// the stream normally -- proves the idle timer resets on every frame
    /// rather than firing on a long-but-healthy stream.
    async fn spawn_upstream_streaming_slowly(frame_count: usize, gap: Duration) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .unwrap();
            for _ in 0..frame_count {
                tokio::time::sleep(gap).await;
                stream.write_all(b"5\r\nhello\r\n").await.unwrap();
            }
            stream.write_all(b"0\r\n\r\n").await.unwrap();
        });
        addr
    }

    /// An upstream that accepts connections in a loop, answering each with a
    /// quick `200 OK` -- used by the S5 tests, which need a *second* request
    /// to actually reach the upstream once a `max_requests` guard has been
    /// released (unlike the one-shot helpers above, whose listener task ends
    /// after a single `accept`).
    async fn spawn_upstream_answers_ok_repeatedly() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf).await;
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                });
            }
        });
        addr
    }

    /// Test-only executor for the h2 mock upstreams below -- same shape as
    /// `codec::LocalExec`, needed only on the *server* side of these tests
    /// (the codec under test supplies its own internally).
    #[derive(Clone)]
    struct TestLocalExec;

    impl<F> hyper::rt::Executor<F> for TestLocalExec
    where
        F: std::future::Future + 'static,
    {
        fn execute(&self, fut: F) {
            tokio::task::spawn_local(fut);
        }
    }

    /// Answer every request on `io` as HTTP/2 with a plain `200 OK`, empty
    /// body -- the common server-side service the h2 mock upstreams below all
    /// share.
    async fn serve_h2_ok_forever(io: tokio::net::TcpStream) {
        let io = hyper_util::rt::TokioIo::new(io);
        let service =
            hyper::service::service_fn(|_req: hyper::Request<hyper::body::Incoming>| async move {
                // Rust note: no `.map_err` needed here (contrast
                // `body_with_trailers`'s use of the same `Full`) -- `Full`'s own
                // `Error` type is `std::convert::Infallible`, which already
                // implements `std::error::Error`, satisfying hyper's server body
                // bound directly.
                Ok::<_, std::convert::Infallible>(
                    hyper::Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                )
            });
        let _ = hyper::server::conn::http2::Builder::new(TestLocalExec)
            .serve_connection(io, service)
            .await;
    }

    /// A loopback HTTP/2 upstream that accepts connections in a loop and
    /// counts how many it has accepted -- what the WP-15 slice A
    /// connection-reuse tests assert against directly: N requests through a
    /// warm/reused connection must NOT increment this past 1.
    async fn spawn_counting_h2_upstream() -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accepted_clone = accepted.clone();
        tokio::task::spawn_local(async move {
            loop {
                let (io, _peer) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                accepted_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::task::spawn_local(serve_h2_ok_forever(io));
            }
        });
        (addr, accepted)
    }

    /// Like [`spawn_counting_h2_upstream`], but its FIRST connection dies the
    /// moment the returned `oneshot::Sender` fires -- simulating an
    /// upstream-initiated close (GOAWAY, or the peer just hanging up)
    /// mid-life rather than a graceful one. Every connection after the first
    /// is served normally, forever, so a redial following the kill succeeds.
    async fn spawn_killable_h2_upstream() -> (
        SocketAddr,
        Arc<std::sync::atomic::AtomicUsize>,
        oneshot::Sender<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accepted_clone = accepted.clone();
        let (kill_tx, kill_rx) = oneshot::channel::<()>();

        tokio::task::spawn_local(async move {
            let (io, _peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            accepted_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let conn_task = tokio::task::spawn_local(serve_h2_ok_forever(io));
            // Wait for the test to say "the first response was received",
            // then kill this connection out from under the client -- proving
            // the NEXT request has to notice (`is_closed()`) and redial
            // rather than hang or fail against a dead sender.
            let _ = kill_rx.await;
            conn_task.abort();

            loop {
                let (io, _peer) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                accepted_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::task::spawn_local(serve_h2_ok_forever(io));
            }
        });

        (addr, accepted, kill_tx)
    }

    /// Like [`spawn_upstream_answers_ok_repeatedly`], but counts how many TCP
    /// connections it has accepted -- what `h1_stays_connect_per_stream`
    /// asserts against to prove slice A's h2 cache didn't accidentally start
    /// reusing h1 connections too.
    async fn spawn_counting_h1_upstream() -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accepted_clone = accepted.clone();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                accepted_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf).await;
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                });
            }
        });
        (addr, accepted)
    }

    /// Build a one-cluster, one-route `RouterHandler` forwarding to `addr`
    /// under cluster name `"up"`.
    /// ADR-0004 step 3: `RouterHandler` is no longer a `StreamHandler` on its
    /// own -- it's the terminal of a filter chain. These tests exercise it
    /// exactly the way production code does: a `FilterChainHandler` with no
    /// other filters, wrapping the router via [`RouterFilterFactory`], whose
    /// `.handle()` (still a `StreamHandler`) drives the whole thing,
    /// including S2.8 route resolution against `route_table` (there is no
    /// more private-resolution fallback for these tests to bypass).
    async fn build_router(
        addr: SocketAddr,
        matcher: RouteMatcher,
        fwd: ForwardAction,
    ) -> FilterChainHandler {
        build_router_with_circuit_breakers(addr, matcher, fwd, CircuitBreakers::default()).await
    }

    /// Like [`build_router`], but threading a custom [`CircuitBreakers`]
    /// through the cluster config -- lets S5 tests set a tight `max_requests`
    /// without hand-building a `ClusterEntry`.
    async fn build_router_with_circuit_breakers(
        addr: SocketAddr,
        matcher: RouteMatcher,
        fwd: ForwardAction,
        circuit_breakers: CircuitBreakers,
    ) -> FilterChainHandler {
        build_router_with_circuit_breakers_and_stats(addr, matcher, fwd, circuit_breakers)
            .await
            .0
    }

    /// Like [`build_router_with_circuit_breakers`], but also hands back the
    /// [`RouterStats`] (and, through it, the
    /// [`proxy_observability::stats::Registry`]) the router was built with --
    /// for the WP-23 increment 6a tests that need to assert on recorded
    /// traffic, not just the response the router returns. Builds a
    /// [`RouterStats`] resolved for cluster `"up"` (the only cluster this
    /// helper's `ClusterManager` ever registers) -- see
    /// [`build_router_with_stats_table`] for the tests that need a
    /// *different* stats table (e.g. one missing `"up"` entirely, to prove
    /// the unknown-cluster no-op path).
    async fn build_router_with_circuit_breakers_and_stats(
        addr: SocketAddr,
        matcher: RouteMatcher,
        fwd: ForwardAction,
        circuit_breakers: CircuitBreakers,
    ) -> (FilterChainHandler, Arc<RouterStats>) {
        let stats = test_router_stats(&["up"]);
        let handler =
            build_router_with_stats_table(addr, matcher, fwd, circuit_breakers, stats.clone())
                .await;
        (handler, stats)
    }

    /// The common builder every `build_router*` helper above bottoms out in:
    /// same one-cluster (`"up"`), one-route `ClusterManager`/`RouteTable` as
    /// [`build_router`], but takes the [`RouterStats`] to build the
    /// [`RouterFilterFactory`] with directly, rather than always resolving a
    /// fresh one for `"up"` -- what lets a test hand in a `RouterStats` that
    /// deliberately does NOT know about `"up"`, to exercise the "unknown
    /// cluster is a no-op, not a panic" path end to end through the real
    /// dispatch code, not just at the `stat_handles` unit-test level.
    async fn build_router_with_stats_table(
        addr: SocketAddr,
        matcher: RouteMatcher,
        fwd: ForwardAction,
        circuit_breakers: CircuitBreakers,
        stats: Arc<RouterStats>,
    ) -> FilterChainHandler {
        let manager = ClusterManager::with_default_transport(Arc::new(FakeResolver::new()));
        let mut snapshot: HashMap<ClusterName, Arc<ClusterConfig>> = HashMap::new();
        snapshot.insert(
            "up".to_string(),
            Arc::new(ClusterConfig {
                name: "up".to_string(),
                discovery: DiscoveryType::Static,
                lb_policy: LbPolicy::RoundRobin,
                connect_timeout: Duration::from_secs(5),
                endpoints: vec![EndpointIR {
                    host: addr.ip().to_string(),
                    port: addr.port(),
                    weight: 1,
                    priority: 0,
                }],
                kind: ClusterKind::Endpoints,
                transport_socket: None,
                per_connection_buffer_limit_bytes: 1 << 20,
                circuit_breakers,
                upstream_protocol: proxy_config::ir::UpstreamProtocol::Http1,
                request_headers_to_add: Vec::new(),
                usage_dialect: None,
                health_check: None,
            }),
        );
        manager.update_from_snapshot(&snapshot).await;

        let route_table = RouteTable::new(
            "test-routes".to_string(),
            vec![VirtualHostIR {
                name: "vh".to_string(),
                domains: vec!["*".to_string()],
                routes: vec![Arc::new(RouteEntry {
                    name: None,
                    matcher,
                    action: RouteActionIR::Forward(fwd),
                    request_headers_to_add: Vec::new(),
                    typed_per_filter_config: BTreeMap::new(),
                    route_index: 0,
                })],
                typed_per_filter_config: BTreeMap::new(),
            }],
            BTreeMap::new(),
        )
        .unwrap();

        let terminal_factory: Arc<dyn TerminalFilterInstanceFactory> =
            Arc::new(RouterFilterFactory::new(Arc::new(manager), stats));
        FilterChainHandler::new(
            Vec::new(),
            terminal_factory,
            Arc::new(route_table),
            false,
            false,
            0,
        )
    }

    /// Like [`build_router`], but the cluster's `upstream_protocol` is
    /// HTTP/2 -- lets the WP-15 slice A connection-reuse tests exercise the
    /// real `RouterHandler` -> `UpstreamConnCache` path end to end, instead
    /// of poking the cache directly.
    async fn build_router_h2(
        addr: SocketAddr,
        matcher: RouteMatcher,
        fwd: ForwardAction,
    ) -> FilterChainHandler {
        let manager = ClusterManager::with_default_transport(Arc::new(FakeResolver::new()));
        let mut snapshot: HashMap<ClusterName, Arc<ClusterConfig>> = HashMap::new();
        snapshot.insert(
            "up".to_string(),
            Arc::new(ClusterConfig {
                name: "up".to_string(),
                discovery: DiscoveryType::Static,
                lb_policy: LbPolicy::RoundRobin,
                connect_timeout: Duration::from_secs(5),
                endpoints: vec![EndpointIR {
                    host: addr.ip().to_string(),
                    port: addr.port(),
                    weight: 1,
                    priority: 0,
                }],
                kind: ClusterKind::Endpoints,
                transport_socket: None,
                per_connection_buffer_limit_bytes: 1 << 20,
                circuit_breakers: CircuitBreakers::default(),
                upstream_protocol: proxy_config::ir::UpstreamProtocol::Http2,
                request_headers_to_add: Vec::new(),
                usage_dialect: None,
                health_check: None,
            }),
        );
        manager.update_from_snapshot(&snapshot).await;

        let route_table = RouteTable::new(
            "test-routes".to_string(),
            vec![VirtualHostIR {
                name: "vh".to_string(),
                domains: vec!["*".to_string()],
                routes: vec![Arc::new(RouteEntry {
                    name: None,
                    matcher,
                    action: RouteActionIR::Forward(fwd),
                    request_headers_to_add: Vec::new(),
                    typed_per_filter_config: BTreeMap::new(),
                    route_index: 0,
                })],
                typed_per_filter_config: BTreeMap::new(),
            }],
            BTreeMap::new(),
        )
        .unwrap();

        let terminal_factory: Arc<dyn TerminalFilterInstanceFactory> = Arc::new(
            RouterFilterFactory::new(Arc::new(manager), test_router_stats(&["up"])),
        );
        FilterChainHandler::new(
            Vec::new(),
            terminal_factory,
            Arc::new(route_table),
            false,
            false,
            0,
        )
    }

    fn prefix_matcher(prefix: &str) -> RouteMatcher {
        RouteMatcher {
            path: PathMatch::Prefix(prefix.to_string()),
            case_sensitive: true,
            headers: Vec::new(),
        }
    }

    fn forward_to_up(
        timeout: Option<Duration>,
        host_rewrite_literal: Option<String>,
        prefix_rewrite: Option<String>,
    ) -> ForwardAction {
        ForwardAction {
            target: ForwardTarget::Cluster("up".to_string()),
            timeout,
            idle_timeout: None,
            retry_policy: None,
            host_rewrite_literal,
            prefix_rewrite,
        }
    }

    fn forward_to_up_with_idle_timeout(idle_timeout: Option<Duration>) -> ForwardAction {
        ForwardAction {
            target: ForwardTarget::Cluster("up".to_string()),
            timeout: None,
            idle_timeout,
            retry_policy: None,
            host_rewrite_literal: None,
            prefix_rewrite: None,
        }
    }

    fn request(path: &'static str) -> HttpRequestParts {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::HOST, HeaderValue::from_static("test.local"));
        HttpRequestParts {
            head: RequestHeaders {
                method: Method::GET,
                uri: Uri::from_static(path),
                headers,
            },
            body: local_boxed(
                Full::new(Bytes::new())
                    .map_err(|infallible: std::convert::Infallible| match infallible {}),
            ),
            downstream: DownstreamInfo::loopback(),
        }
    }

    // Rust note: `send_upstream_http1` (like the downstream h1 codec) uses
    // hyper's client, which spawns non-`Send` per-connection driver tasks via
    // `tokio::task::spawn_local` -- so every test that reaches it needs a
    // `LocalSet` running on a `current_thread` runtime, exactly like
    // `tests/http1_upstream_codec.rs`.

    #[tokio::test(flavor = "current_thread")]
    async fn prefix_rewrite_is_applied_to_the_upstream_request_line() {
        LocalSet::new()
            .run_until(async {
                let (addr, rx) = spawn_reflecting_upstream().await;
                let router = build_router(
                    addr,
                    prefix_matcher("/v1/"),
                    forward_to_up(None, None, Some("/".to_string())),
                )
                .await;

                let resp = router.handle(request("/v1/chat/completions")).await;
                assert_eq!(resp.head.status, StatusCode::OK);

                let upstream_request = rx.await.unwrap();
                assert!(
                    upstream_request.starts_with("GET /chat/completions HTTP/1.1"),
                    "expected the rewritten path on the wire, got: {upstream_request:?}"
                );
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn host_rewrite_literal_sets_the_upstream_host_header() {
        LocalSet::new()
            .run_until(async {
                let (addr, rx) = spawn_reflecting_upstream().await;
                let router = build_router(
                    addr,
                    prefix_matcher("/v1/"),
                    forward_to_up(None, Some("upstream.internal".to_string()), None),
                )
                .await;

                let resp = router.handle(request("/v1/chat/completions")).await;
                assert_eq!(resp.head.status, StatusCode::OK);

                let upstream_request = rx.await.unwrap().to_ascii_lowercase();
                assert!(
                    upstream_request.contains("host: upstream.internal"),
                    "expected the rewritten Host header on the wire, got: {upstream_request:?}"
                );
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn route_timeout_sets_the_expected_rq_timeout_header() {
        LocalSet::new()
            .run_until(async {
                let (addr, rx) = spawn_reflecting_upstream().await;
                let router = build_router(
                    addr,
                    prefix_matcher("/v1/"),
                    forward_to_up(Some(Duration::from_secs(2)), None, None),
                )
                .await;

                let resp = router.handle(request("/v1/chat/completions")).await;
                assert_eq!(resp.head.status, StatusCode::OK);

                let upstream_request = rx.await.unwrap().to_ascii_lowercase();
                assert!(
                    upstream_request.contains("x-envoy-expected-rq-timeout-ms: 2000"),
                    "expected the expected-timeout header on the wire, got: {upstream_request:?}"
                );
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn s4_route_timeout_fires_as_a_504() {
        LocalSet::new()
            .run_until(async {
                let addr = spawn_hanging_upstream().await;
                let router = build_router(
                    addr,
                    prefix_matcher("/v1/"),
                    forward_to_up(Some(Duration::from_millis(80)), None, None),
                )
                .await;

                let resp = tokio::time::timeout(
                    Duration::from_secs(2),
                    router.handle(request("/v1/chat/completions")),
                )
                .await
                .expect("the router itself should time the request out, not hang");

                assert_eq!(resp.head.status, StatusCode::GATEWAY_TIMEOUT);
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn no_route_timeout_does_not_spuriously_time_out() {
        LocalSet::new()
            .run_until(async {
                let (addr, _rx) = spawn_reflecting_upstream().await;
                let router = build_router(
                    addr,
                    prefix_matcher("/v1/"),
                    forward_to_up(None, None, None),
                )
                .await;

                let resp = tokio::time::timeout(
                    Duration::from_secs(2),
                    router.handle(request("/v1/chat/completions")),
                )
                .await
                .expect("should complete well within the test's own guard timeout");

                assert_eq!(resp.head.status, StatusCode::OK);
            })
            .await;
    }

    /// A request matching no route still yields a 404. Pre-ADR-0004-step-3
    /// this also asserted the `NoRouteFound` response flag by injecting a
    /// `Rc<RefCell<StreamInfo>>` directly via `req.stream_info` -- that seam
    /// is exactly what step 3 deletes (the router no longer receives a
    /// bespoke `StreamInfo` handle; it reads/writes the ONE the filter chain
    /// owns internally through `cb.stream_info()`, which isn't reachable
    /// from outside a request without wiring an access logger). The flag
    /// itself is still set (see `route_and_forward`'s `None` arm) and is
    /// covered from the access-log side by `tests/router_access_log.rs`;
    /// this test keeps the one assertion that's still observable through the
    /// public `StreamHandler` seam.
    #[tokio::test(flavor = "current_thread")]
    async fn no_route_match_yields_404() {
        LocalSet::new()
            .run_until(async {
                let (addr, _rx) = spawn_reflecting_upstream().await;
                let router = build_router(
                    addr,
                    prefix_matcher("/configured-only"),
                    forward_to_up(None, None, None),
                )
                .await;

                let resp = router.handle(request("/does-not-match")).await;
                assert_eq!(resp.head.status, StatusCode::NOT_FOUND);
                let _ = resp.body.collect().await;
            })
            .await;
    }

    // NOTE (ADR-0004 step 3): the test that used to live here,
    // `req_route_from_chain_is_used_instead_of_private_resolution`, pinned a
    // behavior this step deliberately removes: `RouterHandler` used to fall
    // back to matching its OWN `route_table` privately whenever a request
    // didn't arrive with a chain-resolved `req.route` already attached, and
    // the test proved the chain-resolved route always won over that private
    // fallback. Step 3 deletes the private fallback entirely -- the router
    // now has no `route_table` of its own at all and always reads the
    // filter-manager-cached route via `cb.route()` (S2.8) -- so there is no
    // longer a second code path for a chain-resolved route to "win against".
    // Every other test in this module already exercises the router
    // forwarding via the ONLY route-resolution path that still exists (the
    // `FilterChainHandler`'s route table, through `build_router`), so no
    // coverage is lost; this test's specific premise is gone, not just its
    // plumbing.

    #[tokio::test(flavor = "current_thread")]
    async fn response_idle_timeout_fires_mid_stream() {
        tokio::time::timeout(Duration::from_secs(2), async {
            LocalSet::new()
                .run_until(async {
                    let addr = spawn_upstream_that_stalls_mid_body().await;
                    let router = build_router(
                        addr,
                        prefix_matcher("/v1/"),
                        forward_to_up_with_idle_timeout(Some(Duration::from_millis(80))),
                    )
                    .await;

                    let resp = router.handle(request("/v1/chat/completions")).await;
                    assert_eq!(resp.head.status, StatusCode::OK);

                    // The first frame ("hello") should arrive fine; once the
                    // upstream stalls, the idle timeout must surface as a
                    // `BodyError` rather than the collect hanging forever.
                    let collected = resp.body.collect().await;
                    match collected {
                        Ok(collected) => {
                            // Some hyper/http-body-util versions surface the
                            // first frame before the error is observed; if
                            // `collect()` somehow returned `Ok`, that itself
                            // is a failure of this test's premise.
                            panic!(
                                "expected the idle timeout to surface as an error, got a complete body: {:?}",
                                collected.to_bytes()
                            );
                        }
                        Err(err) => {
                            let msg = err.to_string();
                            assert!(
                                msg.contains("idle timeout"),
                                "expected an idle-timeout error, got: {msg}"
                            );
                        }
                    }
                })
                .await;
        })
        .await
        .expect("the idle timeout should fire well within the test's own guard timeout");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn response_idle_timeout_does_not_kill_an_active_stream() {
        tokio::time::timeout(Duration::from_secs(2), async {
            LocalSet::new()
                .run_until(async {
                    let addr = spawn_upstream_streaming_slowly(4, Duration::from_millis(30)).await;
                    let router = build_router(
                        addr,
                        prefix_matcher("/v1/"),
                        forward_to_up_with_idle_timeout(Some(Duration::from_millis(100))),
                    )
                    .await;

                    let resp = router.handle(request("/v1/chat/completions")).await;
                    assert_eq!(resp.head.status, StatusCode::OK);

                    let collected = resp
                        .body
                        .collect()
                        .await
                        .expect("frames spaced under the idle timeout must not be reset")
                        .to_bytes();
                    assert_eq!(collected.as_ref(), b"hellohellohellohello");
                })
                .await;
        })
        .await
        .expect("should complete well within the test's own guard timeout");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn no_idle_timeout_does_not_wrap_or_spuriously_error() {
        tokio::time::timeout(Duration::from_secs(2), async {
            LocalSet::new()
                .run_until(async {
                    let addr = spawn_upstream_streaming_slowly(2, Duration::from_millis(10)).await;
                    let router = build_router(
                        addr,
                        prefix_matcher("/v1/"),
                        forward_to_up_with_idle_timeout(None),
                    )
                    .await;

                    let resp = router.handle(request("/v1/chat/completions")).await;
                    assert_eq!(resp.head.status, StatusCode::OK);

                    let collected = resp
                        .body
                        .collect()
                        .await
                        .expect("no idle_timeout configured means no wrapping, no spurious error")
                        .to_bytes();
                    assert_eq!(collected.as_ref(), b"hellohello");
                })
                .await;
        })
        .await
        .expect("should complete well within the test's own guard timeout");
    }

    fn circuit_breakers_with_max_requests(max_requests: u32) -> CircuitBreakers {
        CircuitBreakers {
            default: CircuitBreakerThresholds {
                max_requests,
                ..CircuitBreakerThresholds::ENVOY_DEFAULT
            },
            high: CircuitBreakerThresholds::ENVOY_DEFAULT,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn max_requests_sheds_a_second_request_while_the_first_streams() {
        tokio::time::timeout(Duration::from_secs(2), async {
            LocalSet::new()
                .run_until(async {
                    // Headers arrive, then the upstream stalls mid-body --
                    // the first response's `GuardedBody` (wrapping the S5
                    // permit) is therefore still held open when the second
                    // request is fired.
                    let addr = spawn_upstream_that_stalls_mid_body().await;
                    let router = build_router_with_circuit_breakers(
                        addr,
                        prefix_matcher("/v1/"),
                        forward_to_up(None, None, None),
                        circuit_breakers_with_max_requests(1),
                    )
                    .await;

                    let first = router.handle(request("/v1/chat/completions")).await;
                    assert_eq!(first.head.status, StatusCode::OK);

                    let second = router.handle(request("/v1/chat/completions")).await;
                    assert_eq!(second.head.status, StatusCode::SERVICE_UNAVAILABLE);
                    assert_eq!(
                        second.head.headers.get("x-envoy-overloaded").unwrap(),
                        "true"
                    );

                    // Keep the first response body alive for the whole test
                    // -- dropping it earlier would release the guard and
                    // undermine the premise that the second request is shed
                    // while the first is still active.
                    drop(first.body);
                })
                .await;
        })
        .await
        .expect("should complete well within the test's own guard timeout");
    }

    /// WP-23 increment 6a: the S5 circuit breaker rejects the second attempt
    /// before host selection ever runs, so that attempt was never dialed --
    /// it must not add an `upstream_rq_time` observation (a zero-duration
    /// entry for an attempt that never reached the upstream would corrupt
    /// the P50), and, symmetrically, must not increment `upstream_rq` either
    /// (matching Envoy: a `max_requests` rejection is
    /// `upstream_rq_pending_overflow`/`upstream_rq_overflow`, never
    /// `upstream_rq_total`). Only the first (accepted) attempt should be
    /// reflected in either instrument.
    #[tokio::test(flavor = "current_thread")]
    async fn circuit_breaker_rejection_does_not_add_a_histogram_observation() {
        tokio::time::timeout(Duration::from_secs(2), async {
            LocalSet::new()
                .run_until(async {
                    let addr = spawn_upstream_that_stalls_mid_body().await;
                    let (router, stats) = build_router_with_circuit_breakers_and_stats(
                        addr,
                        prefix_matcher("/v1/"),
                        forward_to_up(None, None, None),
                        circuit_breakers_with_max_requests(1),
                    )
                    .await;

                    let first = router.handle(request("/v1/chat/completions")).await;
                    assert_eq!(first.head.status, StatusCode::OK);

                    let second = router.handle(request("/v1/chat/completions")).await;
                    assert_eq!(second.head.status, StatusCode::SERVICE_UNAVAILABLE);

                    let registry = stats.registry();
                    let rendered = proxy_observability::stats::envoy_render::render(&registry);
                    assert!(
                        rendered.contains("cluster.up.upstream_rq_total: 1"),
                        "the shed second attempt must not count against upstream_rq, got:\n{rendered}"
                    );
                    assert_eq!(
                        stats.rq_time_observation_count("up"),
                        Some(1),
                        "the shed second attempt (never dialed) must not add an \
                         upstream_rq_time observation"
                    );

                    drop(first.body);
                })
                .await;
        })
        .await
        .expect("should complete well within the test's own guard timeout");
    }

    /// WP-23 increment 6a: a served request's `upstream_rq_time` observation
    /// must be a real, plausible duration -- not zero, not absent. Bounded
    /// loosely (a few hundred milliseconds is generous for a loopback
    /// reflecting upstream) so this doesn't flake on a slow CI box while
    /// still catching "recorded nothing" or "recorded a bogus huge value"
    /// regressions.
    #[tokio::test(flavor = "current_thread")]
    async fn upstream_rq_time_records_a_plausible_duration_for_a_served_request() {
        LocalSet::new()
            .run_until(async {
                let (addr, _rx) = spawn_reflecting_upstream().await;
                let (router, stats) = build_router_with_circuit_breakers_and_stats(
                    addr,
                    prefix_matcher("/v1/"),
                    forward_to_up(None, None, None),
                    CircuitBreakers::default(),
                )
                .await;

                let resp = router.handle(request("/v1/chat/completions")).await;
                assert_eq!(resp.head.status, StatusCode::OK);

                assert_eq!(
                    stats.rq_time_observation_count("up"),
                    Some(1),
                    "exactly one attempt was dispatched and completed"
                );
                let sum_ms = stats
                    .rq_time_sum_ms("up")
                    .expect("\"up\" has a resolved upstream_rq_time handle");
                assert!(
                    sum_ms > 0.0 && sum_ms < 500.0,
                    "expected a plausible loopback request duration in (0, 500) ms, got {sum_ms}"
                );

                let rendered = proxy_observability::stats::envoy_render::render(&stats.registry());
                assert!(
                    rendered.contains("cluster.up.upstream_rq_time:"),
                    "the served request's duration should render under upstream_rq_time, got:\n{rendered}"
                );
            })
            .await;
    }

    /// WP-23 increment 6a: `ClusterManager` (routing/dialing) knows about
    /// `"up"`, but the stats handle table this router was built with does
    /// NOT (a config-shaped mismatch this table's boot-time construction
    /// makes possible in principle -- see `stat_handles`'s module doc). The
    /// request must still be served normally: stats recording is a no-op for
    /// an unresolved cluster, never a panic, never a failed request.
    #[tokio::test(flavor = "current_thread")]
    async fn an_attempt_against_a_cluster_missing_from_the_stats_table_does_not_panic() {
        LocalSet::new()
            .run_until(async {
                let (addr, _rx) = spawn_reflecting_upstream().await;
                let router = build_router_with_stats_table(
                    addr,
                    prefix_matcher("/v1/"),
                    forward_to_up(None, None, None),
                    CircuitBreakers::default(),
                    test_router_stats(&[]),
                )
                .await;

                let resp = router.handle(request("/v1/chat/completions")).await;
                assert_eq!(
                    resp.head.status,
                    StatusCode::OK,
                    "an unresolved stats handle must not fail the request"
                );
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn max_requests_permit_is_released_when_the_response_body_completes() {
        tokio::time::timeout(Duration::from_secs(2), async {
            LocalSet::new()
                .run_until(async {
                    let addr = spawn_upstream_answers_ok_repeatedly().await;
                    let router = build_router_with_circuit_breakers(
                        addr,
                        prefix_matcher("/v1/"),
                        forward_to_up(None, None, None),
                        circuit_breakers_with_max_requests(1),
                    )
                    .await;

                    let first = router.handle(request("/v1/chat/completions")).await;
                    assert_eq!(first.head.status, StatusCode::OK);
                    // Fully consuming the body drops the `GuardedBody`,
                    // which drops the S5 guard and frees the one slot.
                    first
                        .body
                        .collect()
                        .await
                        .expect("the one-shot upstream's empty body completes cleanly");

                    let second = router.handle(request("/v1/chat/completions")).await;
                    assert_eq!(
                        second.head.status,
                        StatusCode::OK,
                        "the freed permit should let a new request through"
                    );
                })
                .await;
        })
        .await
        .expect("should complete well within the test's own guard timeout");
    }

    // --- ADR-0004 step 3 payoff: the terminal reads the CHAIN-resolved route ---

    /// A decode filter that rewrites `:path` to `to` and calls
    /// `clear_route_cache()` -- the S2.8/ADR-0004-step-1 half of the test
    /// below. Unlike `filter_manager::tests::RouteProbeFilter` (which can't
    /// be `Send + Sync` because it shares an `Rc` call log with other
    /// probes), this filter carries no shared/interior-mutable state, so it
    /// really can be minted by a genuine [`FilterInstanceFactory`] and ride
    /// through the production `FilterChainHandler`/`RouterHandler` path
    /// rather than `FilterManager` driven directly.
    struct RewriteToFilter {
        to: &'static str,
    }

    impl HttpFilter for RewriteToFilter {
        fn decode_headers(
            &mut self,
            cb: &mut dyn DecoderCallbacks,
            headers: &mut RequestHeaders,
            _end_stream: bool,
        ) -> FilterHeadersStatus {
            // Force the ORIGINAL path to actually be resolved and cached
            // first -- otherwise `clear_route_cache()` would have nothing
            // stale to invalidate, and this test wouldn't distinguish "the
            // cache was genuinely cleared" from "nothing was ever cached".
            let _ = cb.route();
            headers.uri = Uri::from_static(self.to);
            cb.clear_route_cache();
            FilterHeadersStatus::Continue
        }
    }

    struct RewriteToFilterFactory {
        to: &'static str,
    }

    impl FilterInstanceFactory for RewriteToFilterFactory {
        fn create_filter(&self) -> Box<dyn HttpFilter> {
            Box::new(RewriteToFilter { to: self.to })
        }
    }

    /// Two `DirectResponse` routes, distinguished only by status code -- the
    /// simplest observable difference, so which one the terminal actually
    /// acted on is visible in the response without a live upstream.
    fn direct_response_route_table() -> RouteTable {
        fn route(prefix: &str, status: u16) -> Arc<RouteEntry> {
            Arc::new(RouteEntry {
                name: None,
                matcher: prefix_matcher(prefix),
                action: RouteActionIR::DirectResponse { status, body: None },
                request_headers_to_add: Vec::new(),
                typed_per_filter_config: BTreeMap::new(),
                route_index: 0,
            })
        }
        RouteTable::new(
            "test-routes".to_string(),
            vec![VirtualHostIR {
                name: "vh".to_string(),
                domains: vec!["*".to_string()],
                routes: vec![route("/a", 201), route("/b", 202)],
                typed_per_filter_config: BTreeMap::new(),
            }],
            BTreeMap::new(),
        )
        .expect("two non-overlapping prefixes on one domain is a valid table")
    }

    /// The payoff of ADR-0004 steps 1 and 3 together, and inexpressible
    /// before either landed: a decode filter rewrites `:path` from `/a/...`
    /// to `/b/...` and calls `clear_route_cache()`; the terminal -- the real
    /// [`RouterHandler`], not a test stand-in -- must act on route `/b`, not
    /// the route that matched the ORIGINAL request.
    ///
    /// Before step 3, `RouterHandler` was a `StreamHandler` that resolved
    /// its own route privately, off the request as it was handed across the
    /// seam -- there was no `DecoderCallbacks::route()` for it to read at
    /// all, so a decode filter's rewrite + `clear_route_cache()` had nothing
    /// to reach. Before step 1, `route()`/`clear_route_cache()` existed as
    /// callback signatures but did nothing (`ChainCtx.route` was never
    /// populated). Only with both in place does "the chain resolved a
    /// different route" and "the terminal reads that resolution" hold at
    /// the same time.
    #[tokio::test(flavor = "current_thread")]
    async fn terminal_forwards_to_the_route_the_chain_resolved_after_a_rewrite() {
        LocalSet::new()
            .run_until(async {
                let route_table = direct_response_route_table();
                let manager = ClusterManager::with_default_transport(Arc::new(FakeResolver::new()));
                let terminal_factory: Arc<dyn TerminalFilterInstanceFactory> = Arc::new(
                    RouterFilterFactory::new(Arc::new(manager), test_router_stats(&[])),
                );
                let rewrite_factory: Arc<dyn FilterInstanceFactory> =
                    Arc::new(RewriteToFilterFactory { to: "/b/x" });
                let handler = FilterChainHandler::new(
                    vec![rewrite_factory],
                    terminal_factory,
                    Arc::new(route_table),
                    false,
                    false,
                    0,
                );

                let resp = handler.handle(request("/a/x")).await;
                assert_eq!(
                    resp.head.status.as_u16(),
                    202,
                    "the rewrite + clear_route_cache() must steer the terminal \
                     onto route /b (status 202), not the originally-matched \
                     route /a (status 201)"
                );
            })
            .await;
    }

    // ------------------------------------------- WP-15 slice A: h2 reuse --

    /// An h2 upstream that answers `RST_STREAM(REFUSED_STREAM)` to the first
    /// `refusals` streams it is asked to serve, then serves 200 forever.
    ///
    /// Raw `h2::server` rather than hyper: hyper's server always intends to
    /// serve a stream and gives no way to refuse one, and a REFUSED_STREAM
    /// that never reaches the wire would make these tests prove nothing.
    /// Counts connections too, since the router invalidates its connection
    /// cache on a codec error and therefore redials before retrying.
    async fn spawn_stream_refusing_h2_upstream(
        refusals: usize,
    ) -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let remaining = Arc::new(AtomicUsize::new(refusals));
        let streams_seen = Arc::new(AtomicUsize::new(0));
        let remaining_outer = remaining.clone();
        let seen_outer = streams_seen.clone();

        tokio::task::spawn_local(async move {
            loop {
                let (io, _peer) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                let remaining = remaining_outer.clone();
                let seen = seen_outer.clone();
                tokio::task::spawn_local(async move {
                    let Ok(mut conn) = h2::server::handshake(io).await else {
                        return;
                    };
                    while let Some(accepted) = conn.accept().await {
                        let Ok((_req, mut respond)) = accepted else {
                            return;
                        };
                        seen.fetch_add(1, Ordering::SeqCst);
                        // `fetch_update` rather than load-then-store: two
                        // streams can be in flight on one h2 connection, and
                        // a non-atomic decrement could refuse more than
                        // `refusals` of them.
                        let refuse = remaining
                            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                            .is_ok();
                        if refuse {
                            respond.send_reset(h2::Reason::REFUSED_STREAM);
                        } else {
                            let _ = respond.send_response(http::Response::new(()), true);
                        }
                    }
                });
            }
        });

        (addr, streams_seen)
    }

    fn refused_stream_retry_policy() -> proxy_config::ir::RetryPolicyIR {
        proxy_config::ir::RetryPolicyIR {
            retry_on: proxy_config::ir::RetryOn::parse("refused-stream"),
            num_retries: 1,
            per_try_timeout: None,
            retriable_status_codes: Vec::new(),
            retry_back_off: proxy_config::ir::RetryBackOff {
                base_interval: Duration::from_millis(1),
                max_interval: Duration::from_millis(2),
            },
            host_selection_retry_max_attempts: 1,
        }
    }

    /// WP-15: `retry_on: refused-stream` end to end, on a real RST_STREAM.
    ///
    /// This trigger has been configurable, documented, and switched on by
    /// every config this repo's format produces since S3 landed, and until
    /// the codec learned to decode the reason it could never fire once --
    /// `AttemptOutcome::RefusedStream` had no producer, so a refused stream
    /// projected to `ResetBeforeHeaders` and only matched if the operator
    /// happened to also list `reset`. The upstream here refuses exactly one
    /// stream; a 200 back means the retry engine saw the refusal for what it
    /// was.
    #[tokio::test(flavor = "current_thread")]
    async fn a_refused_stream_is_retried_and_succeeds() {
        LocalSet::new()
            .run_until(async {
                let (addr, streams) = spawn_stream_refusing_h2_upstream(1).await;
                let fwd = ForwardAction {
                    retry_policy: Some(refused_stream_retry_policy()),
                    ..forward_to_up(None, None, None)
                };
                let router = build_router_h2(addr, prefix_matcher("/"), fwd).await;

                let resp = router.handle(request("/")).await;
                assert_eq!(
                    resp.head.status,
                    StatusCode::OK,
                    "a refused stream with `retry_on: refused-stream` must be retried and \
                     succeed, not surface as a 502"
                );
                assert_eq!(
                    streams.load(std::sync::atomic::Ordering::SeqCst),
                    2,
                    "exactly two streams must reach the upstream: the refused one and the \
                     retry. A count of 1 would mean the retry never happened and the 200 came \
                     from somewhere else"
                );
            })
            .await;
    }

    /// The point of the whole slice: N concurrent h2 requests to one cluster
    /// must open exactly ONE TCP connection, not N. `join_all` drives all N
    /// `router.handle()` futures concurrently (each yields at a real network
    /// `.await`, exactly like N real concurrent connections would), so
    /// without the `UpstreamConnCache` single-flight dial coordination this
    /// would open N connections instead.
    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_h2_requests_to_one_cluster_share_one_connection() {
        LocalSet::new()
            .run_until(async {
                let (addr, accepted) = spawn_counting_h2_upstream().await;
                let router =
                    build_router_h2(addr, prefix_matcher("/"), forward_to_up(None, None, None))
                        .await;

                const N: usize = 8;
                let responses =
                    futures::future::join_all((0..N).map(|_| router.handle(request("/")))).await;
                for resp in responses {
                    assert_eq!(resp.head.status, StatusCode::OK);
                }

                assert_eq!(
                    accepted.load(std::sync::atomic::Ordering::SeqCst),
                    1,
                    "{N} concurrent h2 requests to one cluster must open exactly one TCP connection"
                );
            })
            .await;
    }

    /// A second, *sequential* request reuses the first request's connection
    /// -- the simpler, non-racy half of the reuse property above.
    #[tokio::test(flavor = "current_thread")]
    async fn a_second_sequential_h2_request_reuses_the_first_connection() {
        LocalSet::new()
            .run_until(async {
                let (addr, accepted) = spawn_counting_h2_upstream().await;
                let router =
                    build_router_h2(addr, prefix_matcher("/"), forward_to_up(None, None, None))
                        .await;

                let resp1 = router.handle(request("/")).await;
                assert_eq!(resp1.head.status, StatusCode::OK);
                let resp2 = router.handle(request("/")).await;
                assert_eq!(resp2.head.status, StatusCode::OK);

                assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1);
            })
            .await;
    }

    /// Hazard 3: the upstream closing the connection out from under a cached
    /// sender must not wedge the router -- the next request has to notice
    /// (`is_closed()`) and transparently redial, not fail or hang.
    #[tokio::test(flavor = "current_thread")]
    async fn upstream_close_triggers_a_redial_on_the_next_request() {
        LocalSet::new()
            .run_until(async {
                let (addr, accepted, kill_tx) = spawn_killable_h2_upstream().await;
                let router =
                    build_router_h2(addr, prefix_matcher("/"), forward_to_up(None, None, None))
                        .await;

                let resp1 = router.handle(request("/")).await;
                assert_eq!(resp1.head.status, StatusCode::OK);
                assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1);

                kill_tx.send(()).expect("upstream task still alive");
                // Give the abort, and this (single-threaded) LocalSet's
                // client-side connection-driving task, a chance to actually
                // run and notice the close before the next request checks
                // `is_closed()` -- otherwise this test would be racing hyper's
                // internal bookkeeping instead of exercising it.
                tokio::time::sleep(Duration::from_millis(100)).await;

                let resp2 = router.handle(request("/")).await;
                assert_eq!(
                    resp2.head.status,
                    StatusCode::OK,
                    "must succeed by redialing, not fail against the dead sender"
                );
                assert_eq!(
                    accepted.load(std::sync::atomic::Ordering::SeqCst),
                    2,
                    "the redial must open a second TCP connection"
                );
            })
            .await;
    }

    /// h1 is unchanged by this slice: an h1 cluster still opens one
    /// connection per request (`build_router`'s default cluster is h1).
    #[tokio::test(flavor = "current_thread")]
    async fn h1_stays_connect_per_stream() {
        LocalSet::new()
            .run_until(async {
                let (addr, accepted) = spawn_counting_h1_upstream().await;
                let router =
                    build_router(addr, prefix_matcher("/"), forward_to_up(None, None, None)).await;

                let resp1 = router.handle(request("/")).await;
                assert_eq!(resp1.head.status, StatusCode::OK);
                let resp2 = router.handle(request("/")).await;
                assert_eq!(resp2.head.status, StatusCode::OK);

                assert_eq!(
                    accepted.load(std::sync::atomic::Ordering::SeqCst),
                    2,
                    "an h1 cluster must still open one connection per request (no reuse)"
                );
            })
            .await;
    }
}
