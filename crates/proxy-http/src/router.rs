//! Terminal HTTP filter that matches routes, selects a cluster and host, and
//! proxies requests over reusable HTTP/1.1 or HTTP/2 upstream connections.
//! Route transforms, timeouts, retries, hedges, and circuit breakers are
//! applied during forwarding. HCM stream timeouts wrap this filter in
//! `filter_manager`; route idle timeout takes precedence for response body
//! gaps (envoy-divergences.md row 29).
//!
//! Request header transforms run during decode. Response flags and upstream
//! details are recorded in [`StreamInfo`]. Access logging wraps the completed
//! encode chain in [`crate::filter_manager::FilterChainHandler`] so it sees
//! end-of-stream mutations from encoder filters.

use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use http_body_util::{BodyExt, Full};
use proxy_cluster::manager::{ClusterManager, ClusterRegistrySnapshot};
use proxy_cluster::outlier::RequestResult;
use proxy_cluster::pool::ClusterBuildId;
use proxy_cluster::{
    CbGuard, ClusterEntry, LoadBalancerContext, PoolError, RoutingPriority, UpstreamProtocol,
};
use proxy_config::ir::{
    DataSourceIR, ForwardTarget, RedirectIR, RouteActionIR, RouteMatcher, UpgradeConfig,
};
use proxy_observability::stats::instruments;
use proxy_observability::trace::{FinishedSpan, SpanKind, SpanSink, SpanStatus, TraceContext};
use proxy_observability::ResponseFlag;

use crate::codec::UpstreamCodecError;
use crate::credential_provider::{CredentialProvider, ProviderCredentials};
use crate::filter::{
    DecoderCallbacks, FilterDataStatus, FilterHeadersStatus, FilterTrailersStatus, HttpFilter,
    RequestHeaders, RequestTrailers, ResponseHeaders, TerminalFilterInstanceFactory,
    TerminalHttpFilter,
};
use crate::handler::{
    local_boxed, DownstreamInfo, HttpRequestParts, HttpResponseParts, StreamBody, UpgradeTunnel,
};
use crate::retry::{AttemptOutcome, RetryState};
use crate::route::{apply_prefix_rewrite, select_cluster};
use crate::stat_handles::RouterStats;
use crate::tenant_credentials::{
    CredentialSource, TenantCredential, TenantCredentialSet, TenantSecret,
};
use crate::upstream_pool::{ConnKey, H1ConnCache, LeasedH1, PooledSendRequest, UpstreamConnCache};
use guarded::GuardedBody;
use idle::IdleTimeoutBody;

/// A hedge sends a second request before the first has finished, so it is
/// restricted to HTTP's safe methods. Idempotency alone is insufficient:
/// replaying a `PUT` concurrently can still expose intermediate state.
fn hedge_safe_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    )
}

/// What `apply_forward`'s attempt loop got back from connecting to the
/// picked host: a [`LeasedH1`] from the worker's bounded-idle h1 connection
/// cache -- possibly a reused, already-handshaken connection, possibly a
/// freshly dialed one -- or a [`PooledSendRequest`] leased
/// from the worker's bounded h2 connection set -- possibly a clone of an
/// already-cached, already-handshaken sender, possibly a freshly dialed one
/// (h2 connections are cached as a bounded set -- see
/// `crate::upstream_pool`'s module doc). One `Result<Connected, PoolError>`
/// for both protocols keeps the shared connect-failure handling (S3 retry
/// classification, circuit-breaker outcome, response-flag mapping) a single
/// match arm instead of two near-duplicate ones.
enum Connected {
    Http1(LeasedH1),
    Http2(PooledSendRequest),
}

/// A timed-out attempt kept alive while its one budgeted hedge is dispatched.
/// Dropping the request must also cancel the detached local task: unlike an
/// ordinary retry, a hedge intentionally survives its timer, but it must not
/// survive the downstream request or the route-wide timeout.
struct HedgedResponse {
    receiver: tokio::sync::oneshot::Receiver<Result<HttpResponseParts, UpstreamCodecError>>,
    task: tokio::task::JoinHandle<()>,
    dispatched_at: std::time::Instant,
    cluster: String,
    address: std::net::SocketAddr,
    trace: Option<TraceContext>,
    started_system: SystemTime,
    attempt_info: Option<std::rc::Rc<std::cell::RefCell<crate::stream_info::AttemptInfo>>>,
}

impl Drop for HedgedResponse {
    fn drop(&mut self) {
        if let Some(info) = &self.attempt_info {
            info.borrow_mut()
                .finish(proxy_observability::records::Termination::Cancelled);
        }
        self.task.abort();
    }
}

mod guarded;
// Rust note: `pub(crate)` (not private) so `access_logging::LoggingBody`, a
// sibling of `router` rather than a child, can name `idle::IdleTimeoutError`
// to distinguish "upstream went quiet" (SI) from "upstream connection died"
// (UC) when classifying a body error for the access log.
pub(crate) mod idle;

/// ADR-0004 step 3: the router's own [`TerminalFilterInstanceFactory`] --
/// mints a fresh [`RouterHandler`] per stream, exactly like every other
/// filter's factory. `Send + Sync` (required by `TerminalFilterInstanceFactory`,
/// see its doc) because it only holds `Arc`s -- thread-safe config-time
/// state, same shape as `FilterInstanceFactory` implementors.
///
/// `stats` is built once per worker (a fresh
/// [`RouterStats`] carrying that worker's own `WorkerId` -- see
/// `crates/proxy/src/main.rs`'s `worker_main`) and handed in here alongside
/// `clusters`, the same way every other piece of shared, worker-scoped state
/// reaches the router: through the factory that `proxy-core`'s listener
/// wiring builds once per (worker, config version), not through anything
/// resolved per request.
pub struct RouterFilterFactory {
    clusters: ClusterRegistrySnapshot,
    stats: Arc<RouterStats>,
    config_context: Option<(String, u64)>,
    /// This HCM's span sink, if boot/reload wired one --
    /// see [`RouterHandler::span_sink`]'s doc for where it's read.
    span_sink: Option<SpanSink>,
    /// S10: this HCM's `upgrade_configs`, resolved
    /// once (at `with_upgrade_configs`, not per-stream) into "is this
    /// upgrade type enabled?" -- keyed by `UpgradeConfig::upgrade_type`
    /// (already lowercased at lowering, `proxy-config`'s doc on that field).
    /// `Arc<HashMap<..>>`, not `Rc`: `RouterFilterFactory` must stay
    /// `Send + Sync` (every other per-worker field on it is `Arc` for the
    /// same reason -- see `clusters`/`stats` above), but the map itself is
    /// plain, immutable, `Send + Sync` data, so an `Arc` clone into every
    /// stream's `RouterHandler` (see `create_terminal_filter`) costs nothing
    /// `RouterHandler`'s own `!Send` fields (`conn_cache`/`h1_cache`) would.
    /// Empty (the default, and every pre-S10 caller's steady state) means no
    /// upgrade type is ever allowed -- matching Envoy's "no `upgrade_configs`
    /// means no upgrades" default.
    upgrade_configs: Arc<HashMap<String, bool>>,
}

impl RouterFilterFactory {
    pub fn new(clusters: Arc<ClusterManager>, stats: Arc<RouterStats>) -> Self {
        Self {
            clusters: clusters.routing_snapshot(),
            stats,
            config_context: None,
            span_sink: None,
            upgrade_configs: Arc::new(HashMap::new()),
        }
    }

    /// Bind failure diagnostics to the listener and snapshot that built this
    /// router. The tuple is copied only when a local 503 is emitted.
    pub fn with_config_context(mut self, listener: String, version: u64) -> Self {
        self.config_context = Some((listener, version));
        self
    }

    /// Attaches this HCM's span sink -- a builder method,
    /// same shape as `FilterChainHandler::with_tracing` one layer up (every
    /// existing `new` call site stays unaffected; `proxy-core`'s
    /// `build_hcm_handler` calls this whenever `ConfigSnapshot::tracing` is
    /// `Some`).
    pub fn with_tracing(mut self, span_sink: SpanSink) -> Self {
        self.span_sink = Some(span_sink);
        self
    }

    /// S10: attaches this HCM's `upgrade_configs` --
    /// a builder method, same "every existing `new` call site stays
    /// unaffected" shape as [`Self::with_tracing`]. `proxy-core`'s
    /// `build_hcm_handler` calls this for every real HCM build/rebuild with
    /// `hcm.upgrade_configs`; every other caller (tests, and any pre-S10
    /// code path) leaves this unset and gets the empty-map default (no
    /// upgrade type ever allowed).
    pub fn with_upgrade_configs(mut self, configs: Vec<UpgradeConfig>) -> Self {
        self.upgrade_configs = Arc::new(
            configs
                .into_iter()
                .map(|c| (c.upgrade_type, c.enabled))
                .collect(),
        );
        self
    }
}

impl TerminalFilterInstanceFactory for RouterFilterFactory {
    fn create_terminal_filter(&self) -> Box<dyn TerminalHttpFilter> {
        Box::new(
            RouterHandler::new(
                self.clusters.clone(),
                self.stats.clone(),
                self.span_sink.clone(),
                self.upgrade_configs.clone(),
            )
            .with_config_context(self.config_context.clone()),
        )
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
    clusters: ClusterRegistrySnapshot,
    config_context: Option<(String, u64)>,
    /// This worker's `upstream_rq`/`upstream_rq_time`
    /// recorder -- see `apply_forward`'s attempt loop for where it's called
    /// and why.
    stats: Arc<RouterStats>,
    /// This worker's h2 connection-reuse cache. `Rc`, not a
    /// field on `RouterFilterFactory` -- see `upstream_pool::worker_conn_cache`'s
    /// doc for why the factory (which must stay `Send + Sync`) can't hold
    /// this directly, and why a `thread_local!` is the fallback instead.
    /// Fetched fresh per stream (a cheap `Rc` clone -- pointer bump), so
    /// every request this worker serves shares the one underlying cache.
    conn_cache: Rc<UpstreamConnCache>,
    /// This worker's h1 keep-alive connection cache -- same
    /// `Rc`/`thread_local!` shape as `conn_cache` above, for the same reason
    /// (`RouterFilterFactory` must stay `Send + Sync`, so it can't hold this
    /// `!Send` cache directly; see `upstream_pool::worker_h1_conn_cache`'s
    /// doc).
    h1_cache: Rc<H1ConnCache>,
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
    /// This HCM's span sink, if tracing is on --
    /// `apply_forward`'s attempt loop derives a CLIENT [`TraceContext::child`]
    /// of `StreamInfo::trace` (the SERVER context) for each attempt when
    /// this is `Some`, injects its `to_traceparent()` into that attempt's
    /// upstream request headers, and emits a [`FinishedSpan`] through this
    /// sink at the same 4 sites [`report_outlier`] is already called from --
    /// a retry/fallback is a fresh attempt, so it gets a fresh child span
    /// under the SAME server span, never a fresh trace.
    span_sink: Option<SpanSink>,
    /// S10: this HCM's resolved `upgrade_configs`,
    /// cloned (an `Arc` bump) from [`RouterFilterFactory::upgrade_configs`]
    /// at stream construction -- see that field's doc. Read by
    /// [`Self::upgrade_allowed`].
    upgrade_configs: Arc<HashMap<String, bool>>,
}

impl RouterHandler {
    pub fn new(
        clusters: ClusterRegistrySnapshot,
        stats: Arc<RouterStats>,
        span_sink: Option<SpanSink>,
        upgrade_configs: Arc<HashMap<String, bool>>,
    ) -> Self {
        Self {
            clusters,
            config_context: None,
            stats,
            conn_cache: crate::upstream_pool::worker_conn_cache(),
            h1_cache: crate::upstream_pool::worker_h1_conn_cache(),
            captured_head: None,
            captured_body: Bytes::new(),
            captured_trailers: None,
            span_sink,
            upgrade_configs,
        }
    }

    fn with_config_context(mut self, context: Option<(String, u64)>) -> Self {
        self.config_context = context;
        self
    }

    /// S10.1: is `upgrade_type` (already lowercased by the caller -- see
    /// [`requested_upgrade_type`]) both PRESENT in this HCM's
    /// `upgrade_configs` and `enabled` there? Absent entirely, or present
    /// with `enabled: false`, are both "not allowed" -- there is no
    /// third state.
    fn upgrade_allowed(&self, upgrade_type: &str) -> bool {
        self.upgrade_configs
            .get(upgrade_type)
            .copied()
            .unwrap_or(false)
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
        Box::pin(async move {
            let response = self.route_and_forward(cb).await;
            if response.head.status == StatusCode::SERVICE_UNAVAILABLE {
                let route = cb.route();
                let info = cb.stream_info();
                let (listener, version) = self
                    .config_context
                    .as_ref()
                    .map(|(name, version)| (name.as_str(), *version))
                    .unwrap_or(("unknown", 0));
                let Some(suppressed) = local_503_log::admit(
                    listener,
                    info.upstream_cluster.as_deref(),
                    info.response_flags(),
                    tokio::time::Instant::now(),
                ) else {
                    return response;
                };
                tracing::warn!(
                    listener,
                    snapshot_version = version,
                    suppressed,
                    route_name = ?route.as_ref().and_then(|route| route.name.as_deref()),
                    route_index = ?route.as_ref().map(|route| route.route_index),
                    response_code_details = ?info.response_code_details,
                    response_flags = ?info.response_flags(),
                    upstream_cluster = ?info.upstream_cluster,
                    upstream_host = ?info.upstream_host,
                    "local 503 response"
                );
            }
            response
        })
    }
}

/// Repeat suppression for the "local 503 response" warning (AGENTS.md
/// "Fail-open controls"). A sweep that trips a circuit breaker turns every
/// request into a local 503, and one line per 503 makes the log the
/// incident. Only this warning is throttled: access logs and stats still see
/// every 503.
///
/// State is per worker thread, like the upstream connection caches, so the
/// 503 path takes no lock and the healthy path never touches it. The cost is
/// one line per key per worker per interval instead of one per process.
mod local_503_log {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::hash::{Hash, Hasher};
    use std::time::Duration;

    use proxy_observability::ResponseFlag;
    use tokio::time::Instant;

    /// One line per key per worker in this window; the next line reports
    /// how many were dropped.
    pub(super) const INTERVAL: Duration = Duration::from_secs(10);

    /// Keys are bounded by config (listeners x clusters x flag sets), but a
    /// long run of reloads can retire names. Past this many entries, entries
    /// whose window has closed are dropped; a dropped entry's suppressed
    /// count is lost, which only costs a number in a log line.
    const MAX_KEYS: usize = 1024;

    struct Window {
        opened: Instant,
        suppressed: u64,
    }

    thread_local! {
        // Keyed by a hash of (listener, cluster, flags) so a lookup does not
        // allocate. A collision only merges two keys' suppression.
        static WINDOWS: RefCell<HashMap<u64, Window>> = RefCell::new(HashMap::new());
    }

    /// Returns `Some(suppressed)` when this 503 should be logged, where
    /// `suppressed` counts the 503s for the same key that were not logged
    /// since the previous line. Returns `None` when this one is suppressed.
    pub(super) fn admit(
        listener: &str,
        cluster: Option<&str>,
        flags: &[ResponseFlag],
        now: Instant,
    ) -> Option<u64> {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        (listener, cluster, flags).hash(&mut hasher);
        let key = hasher.finish();
        WINDOWS.with(|windows| {
            let mut windows = windows.borrow_mut();
            if let Some(window) = windows.get_mut(&key) {
                if now.duration_since(window.opened) < INTERVAL {
                    window.suppressed += 1;
                    return None;
                }
                let suppressed = std::mem::take(&mut window.suppressed);
                window.opened = now;
                return Some(suppressed);
            }
            if windows.len() >= MAX_KEYS {
                windows.retain(|_, w| now.duration_since(w.opened) < INTERVAL);
            }
            windows.insert(
                key,
                Window {
                    opened: now,
                    suppressed: 0,
                },
            );
            Some(0)
        })
    }
}

/// [`RouterHandler::emit_client_span`]'s payload, bundled purely to keep
/// that method's argument count under clippy's `too_many_arguments`
/// threshold -- the same motivation `proxy-core`'s `RunTerminalFilterCtx`
/// documents for its own bundling. `attempt_trace` (the one thing that
/// decides whether anything happens at all) stays a separate parameter
/// rather than folding into this struct, so a call site's `None`-check
/// reads at the call, not one field deeper.
struct ClientSpanOutcome<'a> {
    cluster: &'a str,
    addr: std::net::SocketAddr,
    start: SystemTime,
    status: SpanStatus,
    outcome: &'a str,
    extra_attributes: Vec<(&'static str, String)>,
}

/// `RouteEntry::include_request_attempt_count`/
/// `include_attempt_count_in_response` (Envoy S9, `x-envoy-attempt-count`),
/// bundled into one struct purely to keep `apply_forward`'s parameter count
/// under clippy's `too_many_arguments` threshold -- same motivation
/// `ClientSpanOutcome` above documents for itself.
struct AttemptCountCfg {
    /// Set `x-envoy-attempt-count` on the upstream request, to this
    /// attempt's 1-based number.
    request: bool,
    /// Set `x-envoy-attempt-count` on the downstream response, to the total
    /// number of attempts made.
    response: bool,
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

        // S10: this request asked for an HTTP
        // upgrade -- `on_upgrade` was moved onto the shared `StreamInfo` by
        // `FilterChainHandler::handle`, right after it was built (see that
        // call site's Rust note). Handled here, before the ordinary
        // per-action match below, on purpose: the S10.1 gate (allowed
        // upgrade type, or 403) has nothing to do with routing at all, and a
        // tunnel only ever makes sense against a `Forward` route -- there's
        // no upstream to tunnel to for a `DirectResponse`/`Redirect`.
        if dcb.stream_info().on_upgrade.is_some() {
            if let Some(resp) = self.handle_upgrade_if_applicable(&head, &route, dcb).await {
                return resp;
            }
            // Fell through: the gate already passed (or there would be a
            // `Some(403)` above), but the route doesn't lead anywhere
            // tunnel-able (no match, or a `DirectResponse`/`Redirect`
            // action). Ordinary per-action handling below runs exactly as it
            // would for a non-upgrade request; the downstream `OnUpgrade`
            // still sitting in `StreamInfo` is simply left unfulfilled,
            // which correctly tells the client no upgrade happened.
        }

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
                        AttemptCountCfg {
                            request: route.include_request_attempt_count,
                            response: route.include_attempt_count_in_response,
                        },
                    )
                    .await
                }
                RouteActionIR::DirectResponse { status, body } => {
                    direct_response(*status, body.as_ref())
                }
                RouteActionIR::Redirect(redirect) => redirect_response(redirect, &head),
            },
        }
    }

    /// S10: the S10.1 gate, plus dispatch to
    /// [`Self::handle_upgrade`] when there's a `Forward` route to tunnel to.
    /// `Some(_)` means this call decided the request's fate outright (a
    /// `403` from the gate, or whatever [`Self::handle_upgrade`] returned);
    /// `None` means "not applicable" -- the caller falls through to ordinary
    /// per-action handling (see its call site's comment for the two cases
    /// that land here: no route matched, or the route isn't `Forward`).
    async fn handle_upgrade_if_applicable(
        &self,
        head: &RequestHeaders,
        route: &Option<Arc<proxy_config::ir::RouteEntry>>,
        dcb: &mut dyn DecoderCallbacks,
    ) -> Option<HttpResponseParts> {
        let requested_type = requested_upgrade_type(&head.headers);
        let allowed = requested_type
            .as_deref()
            .is_some_and(|t| self.upgrade_allowed(t));
        if !allowed {
            tracing::debug!(
                response_flag = "none",
                requested_type = ?requested_type,
                "S10.1: upgrade refused -- no enabled upgrade_configs entry for the \
                 requested type (or no Upgrade header at all)"
            );
            return Some(local_reply(StatusCode::FORBIDDEN, "upgrade not allowed"));
        }

        let route = route.as_ref()?;
        let RouteActionIR::Forward(fwd) = &route.action else {
            return None;
        };
        Some(
            self.handle_upgrade(
                fwd,
                &route.matcher,
                &route.request_headers_to_add,
                head,
                dcb,
            )
            .await,
        )
    }

    /// S10 (extended by S10.2 for h2): forward an
    /// ALLOWED upgrade request to the picked cluster/host, dialing a FRESH
    /// connection via `pool.new_stream()` -- bypassing BOTH `H1ConnCache` and
    /// `UpstreamConnCache` -- and build the tunnel response if (and only if)
    /// the upstream answers the accept status for its protocol (h1: `101`;
    /// h2: exactly `200`, RFC 8441 S4/finding (g) caveat (1)).
    ///
    /// S10.2: TRANSPARENT, same-protocol only. The
    /// downstream mechanism the client used (`head.method == CONNECT` means
    /// h2 extended CONNECT; an ordinary `Upgrade` header means h1) must match
    /// the picked upstream's protocol -- an h1 client can only tunnel to an
    /// h1 upstream, an h2 client only to an h2 upstream. Cross-protocol
    /// bridging (h1 client <-> h2 upstream, or the reverse) would need this
    /// proxy to synthesize/translate the actual WebSocket handshake (compute
    /// `Sec-WebSocket-Accept`, or fabricate the `:protocol` pseudo-header
    /// from nothing) -- deliberately out of scope, so it is
    /// rejected outright with a `502` rather than attempted half-correctly.
    ///
    /// Single attempt, no retries at all (S10.1): unlike [`Self::apply_forward`],
    /// there is no `retry_state`/attempt loop here. An upgrade tunnel isn't an
    /// idempotent request/response exchange that's safe to replay on a
    /// different host -- once a `101` has gone out, the client may already be
    /// writing tunnel bytes downstream, and there is no well-defined way to
    /// "retry" a byte stream that's already in flight.
    ///
    /// Bypassing both caches (rather than just the h1 one) is deliberate even
    /// though this v1 tunnel only ever dials h1 upstreams (h2 is rejected
    /// below): an upgraded connection is consumed whole by the tunnel and can
    /// never be handed back for a future request to reuse, on EITHER
    /// protocol, so there is nothing for either cache to gain by seeing it.
    async fn handle_upgrade(
        &self,
        fwd: &proxy_config::ir::ForwardAction,
        matcher: &RouteMatcher,
        request_headers_to_add: &[proxy_config::ir::HeaderMutation],
        head: &RequestHeaders,
        dcb: &mut dyn DecoderCallbacks,
    ) -> HttpResponseParts {
        let draw = match &fwd.target {
            ForwardTarget::Weighted(w) if w.total_weight > 0 => {
                rand::random::<u64>() % w.total_weight
            }
            _ => 0,
        };
        let Some(cluster_name) = select_cluster(&fwd.target, &head.headers, draw) else {
            let mut info = dcb.stream_info();
            info.set_response_flag(ResponseFlag::NoClusterFound);
            info.response_code_details = Some("cluster_not_found".to_string());
            return local_reply(StatusCode::SERVICE_UNAVAILABLE, "no cluster");
        };
        let cluster_name = cluster_name.to_string();

        let Some(entry) = self.clusters.cluster(&cluster_name) else {
            let mut info = dcb.stream_info();
            info.set_response_flag(ResponseFlag::NoClusterFound);
            info.response_code_details = Some("cluster_not_found".to_string());
            return local_reply(StatusCode::SERVICE_UNAVAILABLE, "unknown cluster");
        };

        // A cluster that exists but has never completed its first
        // resolution/EDS update must NOT reach host selection -- Envoy never
        // publishes a warming cluster to its worker thread-local cluster map
        // at all, so a request routed at one takes the SAME `cluster ==
        // nullptr` path (NC/503) as a wholly unknown cluster on the real
        // wire. We reuse `NoClusterFound` rather than inventing a new
        // `ResponseFlag` for exactly that reason -- `flags.rs`'s module doc
        // requires short codes to match Envoy's vocabulary exactly, and Envoy
        // has no warming-specific one -- and rely on
        // `%RESPONSE_CODE_DETAILS%` (this WP) to make the two conditions
        // distinguishable in the access log instead. Checked here, before
        // `select_host`, so an upstream that's merely mid-DNS-resolution
        // never gets treated as "all hosts ejected" (`UH`) -- see
        // `apply_forward`'s identical check for why BOTH cluster-lookup sites
        // need this (an upgrade request is the bypass risk if only one did).
        if !self.clusters.is_initialized(&cluster_name) {
            let mut info = dcb.stream_info();
            info.set_response_flag(ResponseFlag::NoClusterFound);
            info.response_code_details = Some("cluster_not_warmed".to_string());
            return local_reply(StatusCode::SERVICE_UNAVAILABLE, "cluster not warmed");
        }

        // Single host pick, no `LoadBalancerContext::attempted_clusters`
        // accumulation -- there is no second attempt to steer away from the
        // first one's pick.
        let mut ctx = LoadBalancerContext::default();
        let tenant_set: Option<Arc<TenantCredentialSet>> = dcb
            .stream_info()
            .tenant_credentials
            .clone()
            .filter(|set| !set.is_empty());
        if let Some(set) = &tenant_set {
            ctx.credential_providers = Some(set.providers().clone());
        }
        let sel = match select_host_for_request(entry.as_ref(), &mut ctx) {
            Ok(sel) => sel,
            Err(NoHost::Ineligible(provider)) => {
                self.stats.record_tenant_credential(
                    provider
                        .as_deref()
                        .unwrap_or(instruments::TENANT_CREDENTIAL_NO_PROVIDER),
                    instruments::TENANT_CREDENTIAL_MISSING,
                );
                dcb.stream_info().response_code_details =
                    Some("tenant_credential_missing".to_string());
                return tenant_credential_missing_reply(provider.as_deref());
            }
            Err(NoHost::Unhealthy) => {
                let mut info = dcb.stream_info();
                info.set_response_flag(ResponseFlag::NoHealthyUpstream);
                info.response_code_details = Some("no_healthy_upstream".to_string());
                return local_reply(StatusCode::SERVICE_UNAVAILABLE, "no healthy upstream");
            }
        };
        let host = sel.host;
        // Same "the member, not the routed aggregate, owns
        // credentials/protocol" reasoning `apply_forward`'s own attempt loop
        // documents at length -- see there for the full explanation.
        let (attempt_cluster, attempt_entry): (&str, &dyn ClusterEntry) = match &sel.member {
            Some(m) => (m.name.as_str(), m.entry.as_ref()),
            None => (cluster_name.as_str(), entry.as_ref()),
        };

        let credentials =
            match plan_attempt_credentials(tenant_set.as_deref(), attempt_entry.provider_runtime())
            {
                Ok(plan) => plan,
                Err(refusal) => {
                    let mut info = dcb.stream_info();
                    return credential_refusal_reply(
                        &mut info,
                        &self.stats,
                        attempt_cluster,
                        &refusal,
                    );
                }
            };
        let proto = attempt_entry.upstream_protocol();
        {
            let mut info = dcb.stream_info();
            info.upstream_cluster = Some(attempt_cluster.to_string());
            info.upstream_usage_dialect = attempt_entry.usage_dialect();
            info.upstream_host = Some(host.address.to_string());
            info.protocol = Some(
                match proto {
                    UpstreamProtocol::Http1 => "HTTP/1.1",
                    UpstreamProtocol::Http2 => "HTTP/2",
                }
                .to_string(),
            );
        }

        // Rust note: `head.method` is how `codec::serve_one` preserves "this
        // downstream request arrived as h2 extended CONNECT" through to
        // here -- it deliberately leaves `CONNECT` on the request head even
        // though it also synthesizes an `Upgrade` header (see that call
        // site's own Rust note) so this comparison, not header sniffing,
        // is what tells the two downstream mechanisms apart.
        let downstream_is_h2_connect = head.method == Method::CONNECT;
        let upstream_is_h2 = matches!(proto, UpstreamProtocol::Http2);
        // S10.2: TRANSPARENT, same-protocol only -- see this method's doc.
        // `!=` here is the same as `downstream XOR upstream`: it is true for
        // exactly the two disallowed cross combinations (h1->h2, h2->h1) and
        // false for the two allowed same-protocol ones (h1->h1, h2->h2).
        if downstream_is_h2_connect != upstream_is_h2 {
            tracing::debug!(
                cluster = %attempt_cluster,
                downstream_h2 = downstream_is_h2_connect,
                upstream_h2 = upstream_is_h2,
                "S10.2: cross-protocol websocket bridging requested, rejected"
            );
            return local_reply(
                StatusCode::BAD_GATEWAY,
                "cross-protocol websocket bridging (h1<->h2) is not supported",
            );
        }

        let mut attempt_head = RequestHeaders {
            method: head.method.clone(),
            uri: head.uri.clone(),
            headers: head.headers.clone(),
        };
        apply_request_transforms(fwd, matcher, request_headers_to_add, &mut attempt_head);
        apply_cluster_request_path_rewrite(attempt_entry.request_path_rewrite(), &mut attempt_head);
        let routing_model = dcb.stream_info().routing_model().map(str::to_owned);
        dcb.stream_info().selected_model =
            selected_provider_model(attempt_entry.provider_runtime(), routing_model.as_deref());
        apply_cluster_provider_path_template(
            attempt_entry
                .provider_runtime()
                .and_then(|runtime| runtime.path_template.as_ref()),
            routing_model.as_deref(),
            &mut attempt_head,
        );
        let mut provider_credentials = ProviderCredentials::new(
            attempt_entry.provider_runtime(),
            attempt_entry.request_headers_to_add(),
        );
        let source = match &credentials {
            AttemptCredentials::Platform => CredentialSource::Platform,
            AttemptCredentials::Tenant(slot, secret) => {
                provider_credentials = provider_credentials.with_tenant(slot, secret);
                CredentialSource::Tenant
            }
        };
        if let Err(err) = provider_credentials
            .apply(&mut attempt_head, &self.captured_body)
            .await
        {
            tracing::warn!(cluster = %attempt_cluster, error = %err, "provider credential application failed");
            dcb.stream_info()
                .set_response_flag(ResponseFlag::UpstreamConnectionFailure);
            return local_reply(
                StatusCode::SERVICE_UNAVAILABLE,
                "provider credential failure",
            );
        }
        dcb.stream_info().credential_source = Some(source);
        if let AttemptCredentials::Tenant(slot, _) = &credentials {
            self.stats
                .record_tenant_credential(&slot.provider, instruments::TENANT_CREDENTIAL_APPLIED);
        }

        // Bypass BOTH connection caches: `pool.new_stream()` dials a
        // connection this tunnel will own exclusively (see this method's
        // doc), never `H1ConnCache::get_or_connect_h1`/
        // `UpstreamConnCache::get_or_connect`.
        let pool = attempt_entry.http_pool(&host, proto);
        let attempt_info = {
            let mut info = dcb.stream_info();
            let model = info.selected_model.clone();
            info.begin_attempt(attempt_cluster, &host.address.to_string(), model)
        };
        if let Some(info) = &attempt_info {
            info.borrow_mut().credential_source = Some(source);
        }
        let mut attempt_guard = crate::attempt_logging::AttemptGuard(attempt_info.clone());
        let upstream_stream = match pool.new_stream().await {
            Ok(stream) => stream,
            Err(err) => {
                attempt_guard.finish(proxy_observability::records::Termination::UpstreamError);
                let (flag, msg): (ResponseFlag, &str) = match &err {
                    PoolError::Overflow => (ResponseFlag::UpstreamOverflow, "upstream overloaded"),
                    PoolError::ConnectFailure(_) | PoolError::ConnectTimeout => (
                        ResponseFlag::UpstreamConnectionFailure,
                        "upstream connect failure",
                    ),
                    PoolError::TlsHandshake(_) => (
                        ResponseFlag::UpstreamConnectionFailure,
                        "upstream TLS handshake failure",
                    ),
                    PoolError::ResetBeforeHeaders => {
                        (ResponseFlag::UpstreamRemoteReset, "upstream reset")
                    }
                };
                tracing::debug!(cluster = %attempt_cluster, error = %err, "S10: upgrade dial failed");
                dcb.stream_info().set_response_flag(flag);
                return local_reply(StatusCode::SERVICE_UNAVAILABLE, msg);
            }
        };
        let proxy_cluster::UpstreamStream { io, cb_guard } = upstream_stream;
        // `LEAST_REQUEST` reads this count. It lives as long as `cb_guard`:
        // the declined path ties both to the response body, and the accepted
        // path hands both to `UpgradeTunnel`, held until the bridge ends.
        let active_request = host.begin_request();

        let body_bytes = self.captured_body.clone();
        dcb.stream_info().bytes_received = body_bytes.len() as u64;
        let trailers = self.captured_trailers.as_ref().map(|t| t.0.clone());
        let mut attempt_body: StreamBody = body_with_trailers(body_bytes, trailers);
        if let Some(info) = &attempt_info {
            attempt_body = local_boxed(crate::attempt_logging::AttemptBody::new(
                attempt_body,
                info.clone(),
                false,
            ));
        }

        let upstream_req = HttpRequestParts {
            head: attempt_head,
            body: attempt_body,
            downstream: DownstreamInfo::loopback(),
            // No downstream connection of its own -- this is the router's
            // own synthesised upstream request, same as `apply_forward`'s.
            on_upgrade: None,
        };

        // S10.2: same request/response shape (`HttpRequestParts` in,
        // `(HttpResponseParts, Option<OnUpgrade>)` out), different codec
        // function and different accept status per protocol -- `send` here
        // is a runtime branch on a boxed, already-dialed `io`, not a generic
        // dispatch, so the two codec functions' slightly different `IO`
        // bounds (h1's needs `Send`, h2's doesn't -- `BoxedUpstreamIo` is
        // `Send` regardless) never collide.
        let expected_status = if upstream_is_h2 {
            StatusCode::OK
        } else {
            StatusCode::SWITCHING_PROTOCOLS
        };
        let send_result = if upstream_is_h2 {
            crate::codec::send_upstream_h2_connect(io, upstream_req).await
        } else {
            crate::codec::send_upstream_http1_upgrade(io, upstream_req).await
        };
        let (resp, upstream_on_upgrade) = match send_result {
            Ok(pair) => pair,
            Err(err) => {
                attempt_guard.finish(proxy_observability::records::Termination::UpstreamError);
                tracing::debug!(cluster = %attempt_cluster, error = %err, "S10: upgrade send failed");
                return codec_error_reply(&err, dcb);
            }
        };

        if let Some(info) = &attempt_info {
            info.borrow_mut().status = Some(resp.head.status.as_u16());
        }
        dcb.stream_info().selected_attempt = attempt_info.clone();

        if resp.head.status != expected_status {
            // The upstream declined the upgrade -- pass its response
            // straight through (S10.1/S10.2), no tunnel. `resp.upgrade` is
            // already `None` (set by both `send_upstream_http1_upgrade` and
            // `send_upstream_h2_connect`), and the downstream `OnUpgrade`
            // still in `StreamInfo` is simply never `.take()`n -- correctly
            // telling the CLIENT no upgrade happened. `cb_guard` still has
            // to ride along with this response's body (not just get dropped
            // here): the connection this dial opened is still alive for as
            // long as the body is being read, same reasoning
            // `H1ReuseBody`/`GuardedBody` document for their own guards.
            let mut resp = resp;
            if let Some(info) = &attempt_info {
                resp.body = local_boxed(crate::attempt_logging::AttemptBody::new(
                    resp.body,
                    info.clone(),
                    true,
                ));
            }
            attempt_guard.0 = None;
            resp.body = local_boxed(GuardedBody::new(resp.body, (cb_guard, active_request)));
            return resp;
        }

        // Rust note: both `.take()`s below use a defensive `let...else`
        // rather than `.expect()` -- true panics are avoided even where the
        // invariant SHOULD hold (see each arm's comment for why it should),
        // per this crate's general preference for a safe fallback response
        // over a crashed worker.
        let Some(downstream_on_upgrade) = dcb.stream_info().on_upgrade.take() else {
            // Unreachable in practice: `route_and_forward` only calls
            // `handle_upgrade_if_applicable` (and so this method) when
            // `on_upgrade.is_some()`, and nothing between there and here
            // `.await`s anything that could observe/take it out from under
            // us (single-threaded, no re-entrancy into this stream's
            // `StreamInfo`).
            tracing::error!(
                "S10: upstream answered its accept status but the downstream OnUpgrade was \
                 already gone"
            );
            return local_reply(StatusCode::BAD_GATEWAY, "upgrade handshake failed");
        };
        let Some(upstream_on_upgrade) = upstream_on_upgrade else {
            // Also unreachable: both `send_upstream_http1_upgrade` (`101`)
            // and `send_upstream_h2_connect` (`200`) always return `Some`
            // alongside their respective accept status -- see their docs.
            tracing::error!(
                "S10: upstream answered its accept status but the send codec returned no \
                 OnUpgrade"
            );
            return local_reply(StatusCode::BAD_GATEWAY, "upgrade handshake failed");
        };

        // Only the HTTP handshake is observed; upgraded tunnel bytes are
        // outside the request/response entity-body telemetry boundary.
        attempt_guard.finish(proxy_observability::records::Termination::Complete);

        // Empty body: the tunnel carries every byte from here on over the
        // raw `OnUpgrade` streams, not through this response's `StreamBody`
        // (see `codec::serve_one`'s bridging).
        let body: StreamBody = local_boxed(
            Full::new(Bytes::new())
                .map_err(|infallible: std::convert::Infallible| match infallible {}),
        );
        HttpResponseParts {
            head: resp.head,
            body,
            upgrade: Some(UpgradeTunnel {
                downstream: downstream_on_upgrade,
                upstream: upstream_on_upgrade,
                cb_guard,
                active_request: Some(active_request),
            }),
        }
    }

    /// Emit one CLIENT span for a concluded attempt --
    /// called from the same 4 sites [`report_outlier`] already is, right
    /// after it (see [`Self::span_sink`]'s doc for why the two are
    /// deliberately kept in lockstep). A no-op whenever tracing is off
    /// (`self.span_sink: None`), this attempt had no trace context at all
    /// (`attempt_trace: None` -- only possible when `StreamInfo::trace`
    /// itself was `None`, i.e. tracing off), or this stream's trace was
    /// never sampled -- matching the SERVER span's own sampled-gate in
    /// `access_logging::LoggingBody::finish`.
    fn emit_client_span(&self, attempt_trace: Option<TraceContext>, o: ClientSpanOutcome<'_>) {
        let (Some(sink), Some(ctx)) = (self.span_sink.as_ref(), attempt_trace) else {
            return;
        };
        if !ctx.sampled {
            return;
        }
        let ClientSpanOutcome {
            cluster,
            addr,
            start,
            status,
            outcome,
            extra_attributes,
        } = o;
        let mut attributes = vec![
            ("upstream.cluster", cluster.to_string()),
            ("upstream.host", addr.to_string()),
            ("outcome", outcome.to_string()),
        ];
        attributes.extend(extra_attributes);
        sink.emit(FinishedSpan {
            context: ctx,
            name: format!("upstream {cluster}"),
            kind: SpanKind::Client,
            start,
            end: SystemTime::now(),
            attributes,
            status,
        });
    }

    async fn apply_forward(
        &self,
        fwd: &proxy_config::ir::ForwardAction,
        matcher: &RouteMatcher,
        request_headers_to_add: &[proxy_config::ir::HeaderMutation],
        head: RequestHeaders,
        dcb: &mut dyn DecoderCallbacks,
        attempt_count: AttemptCountCfg,
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
            let mut info = dcb.stream_info();
            info.set_response_flag(ResponseFlag::NoClusterFound);
            info.response_code_details = Some("cluster_not_found".to_string());
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
            let mut info = dcb.stream_info();
            info.set_response_flag(ResponseFlag::NoClusterFound);
            info.response_code_details = Some("cluster_not_found".to_string());
            return local_reply(StatusCode::SERVICE_UNAVAILABLE, "unknown cluster");
        };

        // Same admission check as `handle_upgrade` -- see that call
        // site's Rust note for the full "why NC, not a new flag" reasoning.
        // Both cluster-lookup sites need this, not just this one: an upgrade
        // request never reaches `apply_forward` at all, so without the
        // sibling check there a warming cluster would be bypassable simply by
        // asking for an upgrade.
        if !self.clusters.is_initialized(&cluster_name) {
            tracing::debug!(response_flag = "NC", cluster = %cluster_name, "cluster not warmed");
            let mut info = dcb.stream_info();
            info.set_response_flag(ResponseFlag::NoClusterFound);
            info.response_code_details = Some("cluster_not_warmed".to_string());
            return local_reply(StatusCode::SERVICE_UNAVAILABLE, "cluster not warmed");
        }

        let mut head = head;
        apply_request_transforms(fwd, matcher, request_headers_to_add, &mut head);

        // ADR-0004 step 3: the whole request body is already captured
        // (`self.captured_body`) by the time `respond()` runs -- decode is
        // fully buffered before any filter (including the terminal) sees the
        // request (`filter_manager`'s module doc), so there is no more
        // "streamed straight through vs. collected up front" distinction to
        // make here: every attempt (retried or not) just clones the same,
        // already-in-memory `Bytes` (a refcount bump, never a deep copy).
        // `%BYTES_RECEIVED%` is exact and known up front for the same
        // reason.
        let original_body = self.captured_body.clone();
        dcb.stream_info().bytes_received = original_body.len() as u64;
        // The model and streaming-usage facts the earlier filters routed,
        // authorized and metered on come from a bounded prefix scan; the
        // provider decodes the whole body. Reconcile the two once, here, so
        // every attempt forwards a body that says what the proxy believed.
        let (routed_model, force_include_usage, max_output_tokens) = {
            let info = dcb.stream_info();
            (
                info.requested_model.clone(),
                info.force_include_usage,
                info.max_output_tokens,
            )
        };
        let body_bytes = match reconcile_request_body(
            &original_body,
            routed_model.as_deref(),
            force_include_usage,
            max_output_tokens,
            head.uri.path(),
        ) {
            Ok(None) => original_body,
            Ok(Some(reconciled)) => {
                if let Ok(length) = HeaderValue::from_str(&reconciled.len().to_string()) {
                    head.headers.insert(http::header::CONTENT_LENGTH, length);
                }
                reconciled
            }
            Err(refusal) => {
                if refusal.output_cap {
                    self.stats.record_output_cap_rejected();
                }
                tracing::debug!(
                    reason = %refusal.message,
                    "request body disagrees with routing facts"
                );
                return local_reply(StatusCode::BAD_REQUEST, &refusal.message);
            }
        };
        let trailers = self.captured_trailers.as_ref().map(|t| t.0.clone());

        let mut retry_state = fwd.retry_policy.as_ref().map(RetryState::new);
        if let Some(state) = &mut retry_state {
            // S3.4 (Envoy's `no_retry_body_too_large`): the replay limit is
            // the stream's buffer limit (the listener's
            // `per_connection_buffer_limit_bytes`), as in Envoy, so raising
            // the listener limit also raises the largest retriable body.
            // Replay clones the already-buffered `Bytes`, so it costs no
            // second copy. The request still proceeds when over the limit;
            // it just can't be retried.
            if body_bytes.len() > dcb.decoder_buffer_limit() {
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
        // Built once, outside the loop (not fresh per attempt like
        // `attempt_head` below), because `attempted_clusters` has to
        // accumulate *across* attempts -- an aggregate's second attempt
        // needs to see the first attempt's pick to skip it. `mut` because
        // the loop pushes onto it after every pick.
        let mut ctx = LoadBalancerContext::default();
        // Tenant mode (ADR-0007): a non-empty credential set restricts
        // aggregate member selection and forbids operator credentials.
        let tenant_set: Option<Arc<TenantCredentialSet>> = dcb
            .stream_info()
            .tenant_credentials
            .clone()
            .filter(|set| !set.is_empty());
        if let Some(set) = &tenant_set {
            ctx.credential_providers = Some(set.providers().clone());
        }
        if let Some(policy) = fwd.retry_policy.as_ref() {
            ctx.avoid_previous_hosts = policy.avoid_previous_hosts;
            ctx.host_selection_retry_max_attempts = policy.host_selection_retry_max_attempts;
        }

        // This attempt loop's own 1-based attempt counter, for
        // `x-envoy-attempt-count` (S9) -- incremented at the same point as
        // `self.stats.record_attempt` below ("the attempt is actually
        // dispatched"), so a circuit-breaker or host-selection rejection
        // (which `return`s before that point) never counts as an attempt.
        // Mutated only inside `attempt_loop` below, same as `ctx` and
        // `retry_state`; read again once `attempt_loop` has been consumed
        // (see the Rust note just below for why that's sound).
        let mut attempt_number: u32 = 0;

        // Set only after a per-try timer launches a hedge.  It lives outside
        // the loop because the hedge is the *next* loop iteration; that
        // iteration races this original response with its own newly-issued
        // replay.
        let mut hedged_response: Option<HedgedResponse> = None;
        // Set only after this request is admitted as a retry (ordinary or
        // hedge). It crosses the loop boundary because the budget is held for
        // the retry attempt's full response stream, just like max_requests.
        let mut retry_guard: Option<CbGuard> = None;
        // The last retriable upstream response, kept (body unread) while the
        // next attempt is being set up. If that attempt finds no host left
        // (every aggregate member already tried), the client gets this real
        // response instead of a synthesized `503 no healthy upstream`.
        let mut held_failed_response: Option<HeldFailedResponse> = None;

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
                // Deliberately still `entry` (the *routed* cluster),
                // not the not-yet-known `attempt_entry` a few lines below --
                // this matches Envoy, whose `Router::Filter` checks the
                // routed cluster's `max_requests` before any host selection
                // even runs, not the eventually-dialed host's cluster.
                // Concretely: today an aggregate's members all share the
                // aggregate's own `max_requests` budget (there is no
                // per-member budget to acquire instead -- S5's other three
                // budgets are connection-pool-level and likewise
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
                // A hedge moves the original attempt's guard into its local
                // task; ordinary response handling retains it here.
                let sel = match select_host_for_request(entry.as_ref(), &mut ctx) {
                    Ok(sel) => sel,
                    Err(NoHost::Ineligible(provider)) => {
                        self.stats.record_tenant_credential(
                            provider
                                .as_deref()
                                .unwrap_or(instruments::TENANT_CREDENTIAL_NO_PROVIDER),
                            instruments::TENANT_CREDENTIAL_MISSING,
                        );
                        dcb.stream_info().response_code_details =
                            Some("tenant_credential_missing".to_string());
                        return tenant_credential_missing_reply(provider.as_deref());
                    }
                    Err(NoHost::Unhealthy) if held_failed_response.is_some() => {
                        // A retry was admitted but nothing is left to dial.
                        // Envoy retries against already-tried hosts, so a
                        // client there still sees an upstream answer; return
                        // the last one rather than inventing a 503.
                        let held = held_failed_response.take().expect("checked above");
                        tracing::debug!(
                            cluster = %cluster_name,
                            "retry found no untried host; returning the last upstream response"
                        );
                        let service_time_ms =
                            u64::try_from(held.dispatched_at.elapsed().as_millis())
                                .unwrap_or(u64::MAX);
                        return finalize_upstream_response(
                            held.response,
                            service_time_ms,
                            fwd.idle_timeout,
                            Some(rq_guard),
                            None,
                        );
                    }
                    Err(NoHost::Unhealthy) => {
                        tracing::debug!(response_flag = "UH", cluster = %cluster_name, "no healthy upstream host");
                        let mut info = dcb.stream_info();
                        info.set_response_flag(ResponseFlag::NoHealthyUpstream);
                        info.response_code_details = Some("no_healthy_upstream".to_string());
                        return local_reply(StatusCode::SERVICE_UNAVAILABLE, "no healthy upstream");
                    }
                };
                let host = sel.host;
                if let Some(held) = held_failed_response.take() {
                    // A new attempt is going out, so the earlier failure is
                    // not needed any more. Free its connection if the body is
                    // small, otherwise drop it.
                    drain_failed_attempt_body(held.response.body).await;
                }
                // `LEAST_REQUEST` reads this count. It lives and dies with
                // `rq_guard` (response body, hedge task, or the end of this
                // iteration on retry/error), so each attempt counts once.
                let mut rq_guard = Some((rq_guard, host.begin_request()));
                // `entry` is the *routed* cluster (a plain cluster,
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
                // Tenant mode resolves the credential before anything is
                // dialled or counted as an attempt. An aggregate's filtered
                // pick makes `Missing` unreachable there; it is the real
                // check for a non-aggregate routed cluster.
                let credentials = match plan_attempt_credentials(
                    tenant_set.as_deref(),
                    attempt_entry.provider_runtime(),
                ) {
                    Ok(plan) => plan,
                    Err(refusal) => {
                        let mut info = dcb.stream_info();
                        return credential_refusal_reply(
                            &mut info,
                            &self.stats,
                            attempt_cluster,
                            &refusal,
                        );
                    }
                };
                // Record this attempt's cluster so a retry that falls back
                // to an aggregate skips it on the next pick (see
                // `LoadBalancerContext::attempted_clusters`'s doc). A plain
                // `String` clone, not a borrow, so it doesn't conflict with
                // `attempt_cluster` still being read below.
                ctx.attempted_clusters.push(attempt_cluster.to_string());
                ctx.attempted_hosts.push(host.address);

                // This is "the attempt is actually
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
                attempt_number += 1;
                let attempt_dispatched_at = std::time::Instant::now();

                let proto = attempt_entry.upstream_protocol();
                // Both known right here, at the dial site -- recorded
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
                // This attempt's CLIENT trace context --
                // a fresh `TraceContext::child` of the SERVER span
                // (`StreamInfo::trace`) for EVERY attempt, including a
                // retry/fallback, so each one gets its own child span while
                // all of them stay under the one server span (same
                // trace_id, same parent). `None` when tracing is off, or
                // this stream's server span was itself never minted
                // (impossible once tracing is on, but `StreamInfo::trace`'s
                // type doesn't know that). `attempt_started_system` is this
                // same attempt's wall-clock start, for the CLIENT span's own
                // `start` -- distinct from `attempt_dispatched_at` (an
                // `Instant`, used only for the duration stat) because a span
                // timestamp has to be an absolute epoch offset (see
                // `FinishedSpan`'s own doc for why).
                let (attempt_trace, attempt_started_system, attempt_info) = {
                    let mut info = dcb.stream_info();
                    let routing_model = info.routing_model().map(str::to_owned);
                    info.upstream_cluster = Some(attempt_cluster.to_string());
                    // Written on every attempt, `None` included, so a fallback
                    // member without a dialect never inherits the failed
                    // primary's (AGENTS.md invariant 6). The usage filter reads
                    // it at response headers, after the last attempt.
                    info.upstream_usage_dialect = attempt_entry.usage_dialect();
                    info.upstream_host = Some(host.address.to_string());
                    info.protocol = Some(
                        match proto {
                            UpstreamProtocol::Http1 => "HTTP/1.1",
                            UpstreamProtocol::Http2 => "HTTP/2",
                        }
                        .to_string(),
                    );
                    let attempt_trace = info.trace.map(|ctx| ctx.child());
                    // Pin model attribution before connecting: a failed dial
                    // still belongs to this physical attempt's selected member.
                    info.selected_model = selected_provider_model(
                        attempt_entry.provider_runtime(),
                        routing_model.as_deref(),
                    );
                    let selected_model = info.selected_model.clone();
                    let attempt_info = info.begin_attempt(
                        attempt_cluster,
                        &host.address.to_string(),
                        selected_model,
                    );
                    if let Some(attempt) = &attempt_info {
                        attempt.borrow_mut().trace = attempt_trace;
                    }
                    (attempt_trace, SystemTime::now(), attempt_info)
                };
                let attempt_guard = crate::attempt_logging::AttemptGuard(attempt_info.clone());
                let pool = attempt_entry.http_pool(&host, proto);
                // Both protocols are now cache-key'd --
                // h2 upstreams are reused across requests via this worker's
                // `UpstreamConnCache` (one TCP connection, or a small bounded
                // set of them, per (cluster, address, protocol), multiplexed
                // by hyper's h2 `SendRequest`); h1 upstreams reuse one IDLE
                // keep-alive connection at a time via this worker's
                // `H1ConnCache` -- see `crate::upstream_pool`'s module doc
                // and `H1ConnCache`'s own doc for the conservative
                // reuse-vs-discard rule that makes that safe. `ConnKey`'s
                // `protocol` field is what keeps the two caches' entries from
                // ever being confused with each other.
                //
                // The key also names the cluster *build*, taken from the
                // owning member's connection budget -- the same budget
                // `http_pool` above charges for the dial -- so a cluster that
                // was reloaded with different settings never reuses a
                // connection negotiated under the old ones.
                let conn_key = ConnKey::new(
                    attempt_cluster,
                    host.address,
                    proto,
                    ClusterBuildId::of(attempt_entry.circuit_breaker(RoutingPriority::Default)),
                );
                let connect_result: Result<Connected, PoolError> = match proto {
                    UpstreamProtocol::Http2 => self
                        .conn_cache
                        .get_or_connect(conn_key.clone(), pool.as_ref())
                        .await
                        .map(Connected::Http2),
                    UpstreamProtocol::Http1 => self
                        .h1_cache
                        .clone()
                        .get_or_connect_h1(conn_key.clone(), pool.as_ref())
                        .await
                        .map(Connected::Http1),
                };
                let connected = match connect_result {
                    Ok(connected) => connected,
                    Err(err) => {
                        self.stats
                            .record_attempt_duration_since(attempt_cluster, attempt_dispatched_at);
                        let outcome = AttemptOutcome::from_pool_error(&err);
                        attempt_guard
                            .finish(proxy_observability::records::Termination::UpstreamError);
                        report_outlier(attempt_entry, host.address, &outcome);
                        self.emit_client_span(
                            attempt_trace,
                            ClientSpanOutcome {
                                cluster: attempt_cluster,
                                addr: host.address,
                                start: attempt_started_system,
                                status: SpanStatus::Error,
                                outcome: "connect_failure",
                                extra_attributes: Vec::new(),
                            },
                        );
                        if let Some(state) = &mut retry_state {
                            if state.should_retry(&outcome)
                                && sleep_backoff_and_reserve_retry(state, cb, &mut retry_guard)
                                    .await
                            {
                                continue;
                            }
                        }
                        tracing::warn!(
                            cluster = %attempt_cluster,
                            host = %host.address,
                            error = %err,
                            "upstream connection attempt failed without retry"
                        );
                        // Rust note: bound to `resp` (rather than `return
                        // match err {...}` directly) so the `URX` flag
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
                            // half actually broke. An h2
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
                // Propagate this attempt's CLIENT trace
                // context to the upstream leg -- `HeaderMap::insert`
                // deliberately (not `append`), so this OVERWRITES any
                // `traceparent` the downstream caller sent, rather than
                // sending both. The inbound header already did its job (the
                // JOIN in `FilterChainHandler::handle`, which is what
                // `attempt_trace` is a `child()` of); forwarding it
                // unchanged would have every attempt claim to BE the
                // downstream caller's span instead of a child of this
                // proxy's own server span.
                if let Some(child_ctx) = attempt_trace {
                    if let Ok(value) = HeaderValue::from_str(&child_ctx.to_traceparent()) {
                        attempt_head.headers.insert("traceparent", value);
                    }
                }
                // S9: `VirtualHost.include_request_attempt_count`,
                // denormalized onto the route (`RouteEntry`'s own doc). Set
                // per attempt, not once outside the loop, so a retry
                // overwrites it with the new attempt number rather than
                // resending the first attempt's.
                if attempt_count.request {
                    attempt_head
                        .headers
                        .insert("x-envoy-attempt-count", HeaderValue::from(attempt_number));
                }
                apply_cluster_request_path_rewrite(
                    attempt_entry.request_path_rewrite(),
                    &mut attempt_head,
                );
                let (requested_model, resolved_model) = {
                    let info = dcb.stream_info();
                    (info.requested_model.clone(), info.resolved_model.clone())
                };
                let routing_model = resolved_model.as_deref().or(requested_model.as_deref());
                dcb.stream_info().selected_model =
                    selected_provider_model(attempt_entry.provider_runtime(), routing_model);
                apply_cluster_provider_path_template(
                    attempt_entry
                        .provider_runtime()
                        .and_then(|runtime| runtime.path_template.as_ref()),
                    routing_model,
                    &mut attempt_head,
                );
                // Deny runs per attempt, after the member is chosen, because
                // a fallback can be a provider with a stricter policy. A deny
                // is a final answer, not a retryable failure: the request
                // itself is what the operator refuses for that provider, and
                // failing over from a 400 would quietly send the same body to
                // another provider that never saw the refusal.
                let attempt_body_bytes = match prepare_attempt_body(
                    attempt_entry.provider_runtime(),
                    requested_model.as_deref(),
                    resolved_model.as_deref(),
                    &body_bytes,
                ) {
                    Ok(body) => body,
                    Err(BodyRefusal::FieldNotPermitted(field)) => {
                        tracing::warn!(cluster = %attempt_cluster, field = %field, "request field not permitted by cluster policy");
                        dcb.stream_info().response_code_details =
                            Some("request_field_not_permitted".to_string());
                        return local_reply(
                            StatusCode::BAD_REQUEST,
                            &format!("request field not permitted: {field}"),
                        );
                    }
                    Err(BodyRefusal::Invalid(err)) => {
                        tracing::warn!(cluster = %attempt_cluster, error = %err, "provider model rewrite failed");
                        return local_reply(
                            StatusCode::BAD_REQUEST,
                            "provider model rewrite failed",
                        );
                    }
                };
                if attempt_body_bytes.len() != body_bytes.len() {
                    if let Ok(length) = HeaderValue::from_str(&attempt_body_bytes.len().to_string())
                    {
                        attempt_head
                            .headers
                            .insert(http::header::CONTENT_LENGTH, length);
                    }
                }
                // Credentials run after every decode filter and per-attempt
                // transform. The selected member owns its credential, so a
                // fallback cannot sign or authorize against the primary.
                let mut provider_credentials = ProviderCredentials::new(
                    attempt_entry.provider_runtime(),
                    attempt_entry.request_headers_to_add(),
                );
                let source = match &credentials {
                    AttemptCredentials::Platform => CredentialSource::Platform,
                    AttemptCredentials::Tenant(slot, secret) => {
                        provider_credentials = provider_credentials.with_tenant(slot, secret);
                        CredentialSource::Tenant
                    }
                };
                if let Err(err) = provider_credentials
                    .apply(&mut attempt_head, &attempt_body_bytes)
                    .await
                {
                    tracing::warn!(cluster = %attempt_cluster, error = %err, "provider credential application failed");
                    dcb.stream_info()
                        .set_response_flag(ResponseFlag::UpstreamConnectionFailure);
                    return local_reply(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "provider credential failure",
                    );
                }
                dcb.stream_info().credential_source = Some(source);
                if let AttemptCredentials::Tenant(slot, _) = &credentials {
                    self.stats.record_tenant_credential(
                        &slot.provider,
                        instruments::TENANT_CREDENTIAL_APPLIED,
                    );
                }
                if let Some(info) = &attempt_info {
                    info.borrow_mut().credential_source = Some(source);
                }
                // Rust note: `body_bytes` is plain `Bytes`, cheap
                // (refcounted) to `.clone()` fresh for every attempt --
                // there's no separate "streaming" body anymore (see this
                // function's body-handling doc above).
                let mut attempt_body: StreamBody =
                    body_with_trailers(attempt_body_bytes, trailers.clone());
                if let Some(info) = &attempt_info {
                    attempt_body = local_boxed(crate::attempt_logging::AttemptBody::new(
                        attempt_body,
                        info.clone(),
                        false,
                    ));
                }

                let upstream_req = HttpRequestParts {
                    head: attempt_head,
                    body: attempt_body,
                    downstream: DownstreamInfo::loopback(),
                    // S10: this router-synthesised
                    // upstream request has no downstream connection of its
                    // own to hand an `OnUpgrade` off from -- the real
                    // downstream one is threaded separately once the tunnel
                    // exists.
                    on_upgrade: None,
                };

                // Dispatch on the cluster's configured upstream protocol.
                // Both codecs yield the same
                // `Result<HttpResponseParts, UpstreamCodecError>`; box the
                // future so the two arms share one type. h2 here is
                // prior-knowledge cleartext (h2c) over the pool's raw TCP
                // stream -- no per-request `Connection: close` concept at
                // all. BOTH arms now send over whatever
                // connection `connected` was leased from -- possibly a
                // reused, already-handshaken one, possibly a fresh one this
                // attempt just dialed -- via each cache's own `.send()`
                // (`LeasedH1::send`/`PooledSendRequest::send`, not
                // `codec::send_upstream_http1`/`codec::send_on_http2`
                // directly), so the h2 side stays counted as in-flight
                // against its connection for the whole response, and the h1
                // side can decide (in `H1ReuseBody`'s `Drop`) whether the
                // connection it just used is safe to hand to the NEXT
                // request.
                let send: std::pin::Pin<
                    Box<
                        dyn std::future::Future<
                            Output = Result<HttpResponseParts, UpstreamCodecError>,
                        >,
                    >,
                > = match connected {
                    Connected::Http1(leased) => Box::pin(leased.send(upstream_req)),
                    Connected::Http2(pooled) => Box::pin(pooled.send(upstream_req)),
                };
                let response_info = attempt_info.clone();
                let mut send = Box::pin(async move {
                    let mut guard = attempt_guard;
                    let result = send.await;
                    match result {
                        Ok(mut response) => {
                            if let Some(info) = response_info {
                                info.borrow_mut().status = Some(response.head.status.as_u16());
                                response.body =
                                    local_boxed(crate::attempt_logging::AttemptBody::new(
                                        response.body,
                                        info,
                                        true,
                                    ));
                            }
                            guard.0 = None; // Body now owns terminal observation.
                            Ok(response)
                        }
                        Err(err) => {
                            guard.finish(proxy_observability::records::Termination::UpstreamError);
                            Err(err)
                        }
                    }
                });

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
                let hedge_candidate = fwd.retry_policy.as_ref().is_some_and(|policy| {
                    policy.hedge_on_per_try_timeout
                        && hedge_safe_method(&head.method)
                        && hedged_response.is_none()
                        // A hedge is a replay, so it must be subject to the
                        // exact same trigger, attempt-budget, and buffered-
                        // body checks as an ordinary retry.  In particular,
                        // do not spawn an original-attempt task for a body
                        // `RetryState` has already declared unreplayable.
                        && retry_state.as_ref().is_some_and(|state| {
                            state.should_retry(&AttemptOutcome::PerTryTimeout)
                        })
                });
                let mut response_already_guarded = false;
                // A hedge races its newly-issued retry against the original.
                // Only the former owns `retry_guard`; if the original wins,
                // release the hedge budget immediately rather than pinning it
                // to an unrelated response body.
                let mut response_from_hedge = false;
                // Usually the current loop iteration wins. A hedge can
                // instead return the prior, timed-out attempt's response;
                // retain that attempt's own start so service time never
                // measures from the wrong dispatch.
                let mut winning_attempt_dispatched_at = attempt_dispatched_at;
                let mut winning_attempt_info = attempt_info.clone();
                let mut earlier_winner = None;
                let attempt_result = if let Some(hedge) = hedged_response.as_mut() {
                    // The original request was still alive when the previous
                    // iteration dispatched this replay.  Both sends are now
                    // in flight, and the first response head wins.  A
                    // transport error is *not* a response head, though: the
                    // other live attempt is still allowed to produce one.
                    // Dropping `hedged_response` immediately below aborts
                    // whichever response is still the loser.
                    let result = tokio::select! {
                        first = &mut hedge.receiver => {
                            response_already_guarded = true;
                            match first.expect("hedged attempt task must outlive its receiver") {
                                Ok(response) => {
                                    winning_attempt_dispatched_at = hedge.dispatched_at;
                                    winning_attempt_info = hedge.attempt_info.clone();
                                    earlier_winner = Some((hedge.cluster.clone(), hedge.address, hedge.trace, hedge.started_system));
                                    hedge.attempt_info = None;
                                    Ok(response)
                                }
                                // Envoy discards an error from the timed-out
                                // attempt while the hedge is live.  Let the
                                // newly-issued attempt decide this race
                                // instead of turning a recoverable original
                                // reset into an immediate downstream 503.
                                Err(_) => {
                                    response_already_guarded = false;
                                    response_from_hedge = true;
                                    (&mut send).await
                                }
                            }
                        }
                        second = &mut send => match second {
                            Ok(response) => {
                                response_from_hedge = true;
                                Ok(response)
                            }
                            Err(second_error) => {
                                // Symmetrically, a failed hedge must not
                                // cancel an original that can still return a
                                // response head.  If both fail, preserve the
                                // hedge error so the normal retry/error path
                                // below remains responsible for it.
                                response_already_guarded = true;
                                match (&mut hedge.receiver)
                                    .await
                                    .expect("hedged attempt task must outlive its receiver")
                                {
                                    Ok(response) => {
                                        winning_attempt_dispatched_at = hedge.dispatched_at;
                                        winning_attempt_info = hedge.attempt_info.clone();
                                        earlier_winner = Some((hedge.cluster.clone(), hedge.address, hedge.trace, hedge.started_system));
                                        hedge.attempt_info = None;
                                        Ok(response)
                                    }
                                    Err(_) => Err(second_error),
                                }
                            }
                        },
                    };
                    if result.is_ok() && !response_from_hedge {
                        if let Some(info) = &attempt_info {
                            info.borrow_mut()
                                .finish(proxy_observability::records::Termination::Cancelled);
                        }
                    }
                    hedged_response = None;
                    result
                } else if hedge_candidate {
                    // `timeout(send)` would drop `send` at expiry, which is
                    // exactly right for a retry but the opposite of a hedge.
                    // Drive it in a local task instead; the receiver lets us
                    // race its headers against the timer without cancelling
                    // the original socket/stream.  The task also owns this
                    // attempt's request guard, so its S5 slot remains held
                    // until either it loses the race or its response body is
                    // finally dropped.
                    let (sender, mut receiver) = tokio::sync::oneshot::channel();
                    // Keep `rq_guard` itself in this loop frame.  Moving the
                    // guard value (rather than its `Option` wrapper) makes
                    // the later normal-response path structurally safe: it
                    // can only take a guard that still belongs to this
                    // attempt.
                    let original_guard = rq_guard.take().expect("hedge owns this attempt guard");
                    let task = tokio::task::spawn_local(async move {
                        let result = send.await.map(|mut response| {
                            response.body =
                                local_boxed(GuardedBody::new(response.body, original_guard));
                            response
                        });
                        let _ = sender.send(result);
                    });
                    let d = per_try_timeout.expect("hedging requires per_try_timeout");
                    // `tokio::time::timeout(receiver)` would consume the
                    // receiver on expiry, preventing the next loop
                    // iteration from racing the still-live original request
                    // against its hedge.  Select by mutable borrow instead.
                    let first_response = tokio::select! {
                        result = &mut receiver => Some(result),
                        _ = tokio::time::sleep(d) => None,
                    };
                    match first_response {
                        Some(result) => {
                            response_already_guarded = true;
                            result.expect("hedged attempt task must outlive its receiver")
                        }
                        None => {
                            self.stats.record_attempt_duration_since(
                                attempt_cluster,
                                attempt_dispatched_at,
                            );
                            let outcome = AttemptOutcome::PerTryTimeout;
                            report_outlier(attempt_entry, host.address, &outcome);
                            self.emit_client_span(
                                attempt_trace,
                                ClientSpanOutcome {
                                    cluster: attempt_cluster,
                                    addr: host.address,
                                    start: attempt_started_system,
                                    status: SpanStatus::Error,
                                    outcome: "per_try_timeout_hedged",
                                    extra_attributes: Vec::new(),
                                },
                            );
                            if let Some(state) = &mut retry_state {
                                if state.should_retry(&outcome) {
                                    // A hedge is a retry that starts NOW, so
                                    // consume its one normal retry budget but
                                    // deliberately skip S3.3 backoff.
                                    retry_guard.take();
                                    if let Some(guard) = cb.try_acquire_retry() {
                                        retry_guard = Some(guard);
                                        state.record_attempt();
                                        hedged_response = Some(HedgedResponse {
                                            receiver,
                                            task,
                                            dispatched_at: attempt_dispatched_at,
                                            cluster: attempt_cluster.to_owned(),
                                            address: host.address,
                                            trace: attempt_trace,
                                            started_system: attempt_started_system,
                                            attempt_info: attempt_info.clone(),
                                        });
                                        continue;
                                    }
                                }
                            }
                            task.abort();
                            if let Some(info) = &attempt_info {
                                info.borrow_mut()
                                    .finish(proxy_observability::records::Termination::Timeout);
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
                    }
                } else {
                    match per_try_timeout {
                        Some(d) => match tokio::time::timeout(d, send).await {
                            Ok(result) => result,
                            Err(_elapsed) => {
                                if let Some(info) = &attempt_info {
                                    let mut info = info.borrow_mut();
                                    info.termination =
                                        proxy_observability::records::Termination::Timeout;
                                }
                                self.stats.record_attempt_duration_since(
                                    attempt_cluster,
                                    attempt_dispatched_at,
                                );
                                let outcome = AttemptOutcome::PerTryTimeout;
                                report_outlier(attempt_entry, host.address, &outcome);
                                self.emit_client_span(
                                    attempt_trace,
                                    ClientSpanOutcome {
                                        cluster: attempt_cluster,
                                        addr: host.address,
                                        start: attempt_started_system,
                                        status: SpanStatus::Error,
                                        outcome: "per_try_timeout",
                                        extra_attributes: Vec::new(),
                                    },
                                );
                                if let Some(state) = &mut retry_state {
                                    if state.should_retry(&outcome)
                                        && sleep_backoff_and_reserve_retry(
                                            state,
                                            cb,
                                            &mut retry_guard,
                                        )
                                        .await
                                    {
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
                                record_retry_limit_exceeded_if_applicable(
                                    &retry_state,
                                    &outcome,
                                    dcb,
                                );
                                return local_reply(
                                    StatusCode::GATEWAY_TIMEOUT,
                                    "upstream request timeout",
                                );
                            }
                        },
                        None => send.await,
                    }
                };

                match attempt_result {
                    Ok(resp) => {
                        let winning_entry = earlier_winner
                            .as_ref()
                            .and_then(|winner| self.clusters.cluster(&winner.0));
                        let (outcome_cluster, outcome_addr, outcome_trace, outcome_start) =
                            earlier_winner
                                .as_ref()
                                .map(|w| (w.0.as_str(), w.1, w.2, w.3))
                                .unwrap_or((
                                    attempt_cluster,
                                    host.address,
                                    attempt_trace,
                                    attempt_started_system,
                                ));
                        {
                            let mut info = dcb.stream_info();
                            info.upstream_cluster = Some(outcome_cluster.to_owned());
                            info.upstream_host = Some(outcome_addr.to_string());
                            if let Some(entry) = &winning_entry {
                                info.upstream_usage_dialect = entry.usage_dialect();
                                info.selected_model = selected_provider_model(
                                    entry.provider_runtime(),
                                    info.routing_model(),
                                );
                            }
                            info.selected_attempt = winning_attempt_info.clone();
                        }
                        self.stats.record_attempt_duration_since(
                            outcome_cluster,
                            winning_attempt_dispatched_at,
                        );
                        let outcome = AttemptOutcome::Response(resp.head.status.as_u16());
                        report_outlier(
                            winning_entry.as_deref().unwrap_or(attempt_entry),
                            outcome_addr,
                            &outcome,
                        );
                        self.emit_client_span(
                            outcome_trace,
                            ClientSpanOutcome {
                                cluster: outcome_cluster,
                                addr: outcome_addr,
                                start: outcome_start,
                                status: if resp.head.status.is_server_error() {
                                    SpanStatus::Error
                                } else {
                                    SpanStatus::Ok
                                },
                                outcome: "response",
                                extra_attributes: vec![(
                                    "http.response.status_code",
                                    resp.head.status.as_u16().to_string(),
                                )],
                            },
                        );
                        let retriable = retry_state
                            .as_ref()
                            .is_some_and(|state| state.should_retry(&outcome));
                        if retriable
                            && sleep_backoff_and_reserve_retry(
                                retry_state.as_mut().expect("checked Some above"),
                                cb,
                                &mut retry_guard,
                            )
                            .await
                        {
                            if response_already_guarded || response_from_hedge {
                                // Hedge bookkeeping owns this response's
                                // guards; just release it.
                                drain_failed_attempt_body(resp.body).await;
                            } else {
                                held_failed_response = Some(HeldFailedResponse {
                                    response: resp,
                                    dispatched_at: winning_attempt_dispatched_at,
                                });
                            }
                            continue;
                        }
                        // This is the one `URX` site that isn't
                        // paired with a synthesized `local_reply` -- `resp`
                        // is the real (failing) upstream response, passed
                        // through unmodified; the only flag it can carry at
                        // all is this one.
                        record_retry_limit_exceeded_if_applicable(&retry_state, &outcome, dcb);
                        // Report this proxy's final upstream attempt,
                        // including connection acquisition and the wait for
                        // response headers. `insert` deliberately replaces a
                        // value supplied by an upstream proxy. Retriable
                        // responses continue above, so discarded attempts
                        // never leak their duration downstream.
                        let service_time_ms =
                            u64::try_from(winning_attempt_dispatched_at.elapsed().as_millis())
                                .unwrap_or(u64::MAX);
                        return finalize_upstream_response(
                            resp,
                            service_time_ms,
                            fwd.idle_timeout,
                            if response_already_guarded {
                                None
                            } else {
                                Some(
                                    rq_guard
                                        .take()
                                        .expect("normal response owns this attempt guard"),
                                )
                            },
                            if !response_already_guarded || response_from_hedge {
                                retry_guard.take()
                            } else {
                                None
                            },
                        );
                    }
                    Err(err) => {
                        self.stats
                            .record_attempt_duration_since(attempt_cluster, attempt_dispatched_at);
                        // A send failure on a cached
                        // h2 sender means it's suspect (e.g. the peer closed
                        // right as we sent) -- evict it so the next
                        // request/retry redials rather than risking the same
                        // now-dead sender again before its `is_closed()`
                        // catches up. h1 needs no equivalent call: a `LeasedH1`
                        // that fails to send is never returned to `H1ConnCache`
                        // in the first place (see `LeasedH1::send`'s `Err` arm),
                        // so there is nothing cached left to invalidate.
                        if matches!(proto, UpstreamProtocol::Http2) {
                            self.conn_cache.invalidate(&conn_key);
                        }
                        let outcome = AttemptOutcome::from_codec_error(&err);
                        report_outlier(attempt_entry, host.address, &outcome);
                        self.emit_client_span(
                            attempt_trace,
                            ClientSpanOutcome {
                                cluster: attempt_cluster,
                                addr: host.address,
                                start: attempt_started_system,
                                status: SpanStatus::Error,
                                outcome: "codec_error",
                                extra_attributes: Vec::new(),
                            },
                        );
                        if let Some(state) = &mut retry_state {
                            if state.should_retry(&outcome)
                                && sleep_backoff_and_reserve_retry(state, cb, &mut retry_guard)
                                    .await
                            {
                                continue;
                            }
                        }
                        // An explicit REMOTE RESET by the peer is `UR`, not a
                        // codec failure -- a refused stream, but also any
                        // other h2 `RST_STREAM` reason (CANCEL, INTERNAL_ERROR,
                        // ...), all of which mean the peer deliberately reset
                        // the stream. That is exactly what Envoy's `UR` means;
                        // see `codec::is_remote_reset` for why REFUSED_STREAM
                        // has its own variant while the rest ride in on a
                        // `Send`/`Connection` with the h2 reason still
                        // recoverable. A connection that merely closed (no h2
                        // reason -- a FIN, or an h1 termination) stays `UC`.
                        // Flag-only: retry classification is unchanged (a
                        // reset before headers is retriable under `reset`
                        // either way).
                        tracing::debug!(cluster = %attempt_cluster, error = %err, "upstream codec error");
                        let resp = codec_error_reply(&err, dcb);
                        record_retry_limit_exceeded_if_applicable(&retry_state, &outcome, dcb);
                        return resp;
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
        let mut resp = match outcome {
            Ok(resp) => resp,
            Err(_elapsed) => {
                for attempt in &dcb.stream_info().attempts {
                    let mut attempt = attempt.borrow_mut();
                    if attempt.termination == proxy_observability::records::Termination::Unknown {
                        attempt.termination = proxy_observability::records::Termination::Timeout;
                        attempt.finish(proxy_observability::records::Termination::Timeout);
                    }
                }
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
        };
        // S9: `VirtualHost.include_attempt_count_in_response`,
        // denormalized onto the route. Set here -- the one place every
        // `attempt_loop` exit (success, exhausted retries, or the whole-route
        // `fwd.timeout` above) converges into the response this function
        // returns -- to the TOTAL attempts made, not just the last one's.
        if attempt_count.response {
            resp.head
                .headers
                .insert("x-envoy-attempt-count", HeaderValue::from(attempt_number));
        }
        resp
    }
}

/// The most bytes read from a failed attempt's body before the attempt is
/// abandoned. Draining lets a small error body finish so its connection can be
/// reused; a body past this size, or one that never ends, is dropped (which
/// resets the stream) instead of being buffered without bound.
const FAILED_ATTEMPT_DRAIN_LIMIT: usize = 64 * 1024;

/// A retriable upstream response kept, body unread, until the next attempt is
/// set up.
struct HeldFailedResponse {
    response: HttpResponseParts,
    /// When the attempt that produced `response` was dispatched, for
    /// `x-envoy-upstream-service-time`.
    dispatched_at: std::time::Instant,
}

/// Read and discard a failed attempt's body, at most
/// [`FAILED_ATTEMPT_DRAIN_LIMIT`] bytes.
async fn drain_failed_attempt_body(mut body: StreamBody) {
    let mut seen = 0usize;
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else { return };
        if let Some(data) = frame.data_ref() {
            seen = seen.saturating_add(data.len());
            if seen > FAILED_ATTEMPT_DRAIN_LIMIT {
                return;
            }
        }
    }
}

/// Final touches on the response that goes back to the client: the
/// `x-envoy-upstream-service-time` header of this proxy's last attempt
/// (`insert` deliberately replaces a value supplied by an upstream proxy), the
/// route `idle_timeout`, then the guards held until the body ends.
fn finalize_upstream_response<G: Unpin + 'static>(
    mut resp: HttpResponseParts,
    service_time_ms: u64,
    idle_timeout: Option<Duration>,
    request_guard: Option<G>,
    retry_guard: Option<CbGuard>,
) -> HttpResponseParts {
    resp.head.headers.insert(
        "x-envoy-upstream-service-time",
        HeaderValue::from(service_time_ms),
    );
    // The route `timeout` bounds the attempt loop, not the body returned
    // here: once headers arrive it has no further deadline (S4), which is what
    // makes LLM-streaming routes safe to bound this way.
    // A zero route `idle_timeout` means "no idle timeout on this route"
    // (Envoy treats 0 as disabled); a zero `IdleTimeoutBody` would instead
    // cut the stream at once.
    if let Some(idle) = idle_timeout.filter(|d| !d.is_zero()) {
        resp.body = local_boxed(IdleTimeoutBody::new(resp.body, idle));
    }
    // S5: wrap outermost (after the idle wrap) so the `max_requests` permit
    // lasts until the last response frame or the body is dropped.
    if let Some(guard) = request_guard {
        resp.body = local_boxed(GuardedBody::new(resp.body, guard));
    }
    if let Some(guard) = retry_guard {
        resp.body = local_boxed(GuardedBody::new(resp.body, guard));
    }
    resp
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
async fn sleep_backoff_and_reserve_retry(
    state: &mut RetryState<'_>,
    cb: &proxy_cluster::CircuitBreakerState,
    retry_guard: &mut Option<CbGuard>,
) -> bool {
    let delay = state.backoff_delay(&mut rand::random::<f64>);
    tokio::time::sleep(delay).await;
    // A prior retry has just finished; it cannot consume a slot while this
    // request asks to issue its next retry. The request guard is still alive
    // in the caller's loop frame, so the percentage denominator remains
    // accurate through this hand-off.
    retry_guard.take();
    let Some(guard) = cb.try_acquire_retry() else {
        return false;
    };
    *retry_guard = Some(guard);
    state.record_attempt();
    true
}

/// The one call site for `ResponseFlag::UpstreamRetryLimitExceeded`
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

/// Report one attempt's outcome to the dialed cluster's S6 outlier detector. Called once per
/// attempt, right where each `AttemptOutcome` is computed and BEFORE the retry decision, so a failed attempt that is then
/// retried still counts against its host -- exactly what Envoy's detector
/// does (every upstream response feeds it, retried or not).
///
/// The mapping is the S6 one:
/// - a real response: 502/503/504 is a `GatewayFailure` (a subset of 5xx that
///   also feeds the gateway detector), any other 5xx is `Http5xx`, everything
///   else is `Success`;
/// - a connect failure, per-try timeout, reset, or refused stream is a
///   `LocalOriginFailure` (folded into the 5xx path, since
///   `split_external_local_origin_errors` is not implemented);
/// - a pool/circuit-breaker overflow is NOT reported at all -- the request was
///   never dispatched to the host, so it is not evidence about the host's
///   health (Envoy counts only issued requests).
fn report_outlier(entry: &dyn ClusterEntry, addr: std::net::SocketAddr, outcome: &AttemptOutcome) {
    if let Some(result) = outlier_result_for(outcome) {
        entry.report_outlier_result(addr, result);
    }
}

/// The pure S6 classification `report_outlier` applies. `None` means "do not
/// report" -- a pool/circuit-breaker overflow was never dispatched to a host,
/// so it is not evidence about that host's health (Envoy counts only issued
/// requests). Split out from [`report_outlier`] so the mapping is unit-testable
/// without a live [`ClusterEntry`].
fn outlier_result_for(outcome: &AttemptOutcome) -> Option<RequestResult> {
    Some(match outcome {
        AttemptOutcome::Response(status) => match status {
            502..=504 => RequestResult::GatewayFailure,
            s if (500..600).contains(s) => RequestResult::Http5xx,
            _ => RequestResult::Success,
        },
        AttemptOutcome::ConnectFailure
        | AttemptOutcome::ResetBeforeHeaders
        | AttemptOutcome::ResetAfterHeaders
        | AttemptOutcome::RefusedStream
        | AttemptOutcome::PerTryTimeout => RequestResult::LocalOriginFailure,
        AttemptOutcome::PoolOverflow => return None,
    })
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
/// head, in place, before it's handed to the upstream send path
/// (`crate::upstream_pool::LeasedH1::send`/`PooledSendRequest::send`):
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

/// Apply provider-owned path/query rewriting after route transforms. The
/// selected aggregate member supplies this value, so fallback requests use
/// fallback provider URL details rather than primary provider details.
fn apply_cluster_request_path_rewrite(
    rewrite: Option<&proxy_config::ir::RequestPathRewrite>,
    head: &mut crate::filter::RequestHeaders,
) {
    let Some(rewrite) = rewrite else {
        return;
    };
    let path = head.uri.path();
    let Some(suffix) = path.strip_prefix(&rewrite.match_prefix) else {
        tracing::debug!(
            path,
            match_prefix = %rewrite.match_prefix,
            "cluster request path rewrite did not match request path"
        );
        return;
    };
    if !suffix.is_empty() && !suffix.starts_with('/') {
        tracing::debug!(
            path,
            match_prefix = %rewrite.match_prefix,
            "cluster request path rewrite matched only a path prefix segment"
        );
        return;
    }

    let mut new_path = rewrite.replacement_prefix.clone();
    if !suffix.is_empty() {
        if !new_path.ends_with('/') && !suffix.starts_with('/') {
            new_path.push('/');
        }
        new_path.push_str(suffix);
    }
    if let Some(query) = &rewrite.query {
        new_path.push('?');
        new_path.push_str(query);
    } else if let Some(query) = head.uri.query() {
        new_path.push('?');
        new_path.push_str(query);
    }

    match http::Uri::builder().path_and_query(new_path).build() {
        Ok(uri) => head.uri = uri,
        Err(err) => {
            tracing::warn!(error = %err, "cluster request path rewrite produced an invalid URI, leaving path unchanged")
        }
    }
}

/// Render provider-owned URL templates after final cluster selection. Model
/// mappings live on the cluster, so a fallback uses its own upstream model
/// identifier rather than the primary's.
fn selected_provider_model(
    runtime: Option<&proxy_config::ir::ProviderRuntimeConfig>,
    requested: Option<&str>,
) -> Option<String> {
    let requested = requested?;
    let mappings = runtime.map(|runtime| match runtime.path_template.as_ref() {
        Some(proxy_config::ir::ProviderPathTemplate::Vertex { models, .. })
        | Some(proxy_config::ir::ProviderPathTemplate::Bedrock { models }) => models.as_slice(),
        None => runtime.model_rewrites.as_slice(),
    });
    Some(
        mappings
            .and_then(|mappings| {
                mappings
                    .iter()
                    .find(|mapping| provider_model_pattern_matches(&mapping.pattern, requested))
                    .map(|mapping| mapping.upstream_model.as_str())
            })
            .unwrap_or(requested)
            .to_string(),
    )
}

fn apply_cluster_provider_path_template(
    template: Option<&proxy_config::ir::ProviderPathTemplate>,
    requested_model: Option<&str>,
    head: &mut crate::filter::RequestHeaders,
) {
    let Some(template) = template else {
        return;
    };
    let Some(requested_model) = requested_model else {
        tracing::warn!("provider path template requires a request model");
        return;
    };
    let upstream_model = |models: &[proxy_config::ir::ProviderModelRewrite]| {
        models
            .iter()
            .find(|mapping| provider_model_pattern_matches(&mapping.pattern, requested_model))
            .map(|mapping| mapping.upstream_model.clone())
            .unwrap_or_else(|| requested_model.to_string())
    };
    let path = match template {
        proxy_config::ir::ProviderPathTemplate::Vertex {
            project,
            location,
            publisher,
            models,
        } => format!(
            "/v1/projects/{}/locations/{}/publishers/{}/models/{}:streamRawPredict",
            path_segment(project),
            path_segment(location),
            path_segment(publisher),
            path_segment(&upstream_model(models)),
        ),
        proxy_config::ir::ProviderPathTemplate::Bedrock { models } => {
            format!("/model/{}/invoke", path_segment(&upstream_model(models)))
        }
    };
    let path_and_query = match head.uri.query() {
        Some(query) => format!("{path}?{query}"),
        None => path,
    };
    match http::Uri::builder().path_and_query(path_and_query).build() {
        Ok(uri) => head.uri = uri,
        Err(err) => tracing::warn!(error = %err, "provider path template produced an invalid URI"),
    }
}

fn provider_model_pattern_matches(pattern: &str, model: &str) -> bool {
    pattern == "*"
        || pattern
            .strip_suffix('*')
            .map_or(pattern == model, |prefix| model.starts_with(prefix))
}

/// Top-level facts the provider's JSON decoder would see in a request body.
#[derive(Default)]
struct BodyDecodeFacts {
    model: Option<serde_json::Value>,
    duplicate_model: bool,
    stream: Option<bool>,
    include_usage: bool,
    /// Every occurrence, in document order, of the output-token limit keys
    /// (see [`OUTPUT_TOKEN_KEYS`]). Kept as a list, not a map, so a repeated
    /// key is visible as a repeat.
    token_limits: Vec<(&'static str, serde_json::Value)>,
}

/// The top-level keys any supported wire format uses to bound output tokens.
const OUTPUT_TOKEN_KEYS: [&str; 3] = ["max_output_tokens", "max_completion_tokens", "max_tokens"];

impl<'de> serde::Deserialize<'de> for BodyDecodeFacts {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Rust note: a `Visitor` is serde's callback interface; `visit_map`
        // is called once with an iterator over the object's entries, so we
        // choose per key whether to materialize the value or skip it.
        struct FactsVisitor;
        impl<'de> serde::de::Visitor<'de> for FactsVisitor {
            type Value = BodyDecodeFacts;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut facts = BodyDecodeFacts::default();
                // `Cow<str>` keys are unescaped exactly as the provider's
                // decoder would unescape them.
                while let Some(key) = map.next_key::<std::borrow::Cow<'de, str>>()? {
                    match key.as_ref() {
                        "model" => {
                            if facts.model.is_some() {
                                facts.duplicate_model = true;
                            }
                            facts.model = Some(map.next_value::<serde_json::Value>()?);
                        }
                        "stream" => {
                            facts.stream = map.next_value::<serde_json::Value>()?.as_bool();
                        }
                        "stream_options" => {
                            // Last wins, matching the provider's decoder.
                            let options = map.next_value::<serde_json::Value>()?;
                            facts.include_usage = options.get("include_usage")
                                == Some(&serde_json::Value::Bool(true));
                        }
                        other => {
                            if let Some(name) = OUTPUT_TOKEN_KEYS.iter().find(|k| **k == other) {
                                let value = map.next_value::<serde_json::Value>()?;
                                facts.token_limits.push((name, value));
                            } else {
                                map.next_value::<serde::de::IgnoredAny>()?;
                            }
                        }
                    }
                }
                Ok(facts)
            }
        }
        deserializer.deserialize_map(FactsVisitor)
    }
}

/// Why [`reconcile_request_body`] refused a body (a local 400).
#[derive(Debug, PartialEq)]
struct Refusal {
    message: String,
    /// The refusal came from the output-token cap, for its counter.
    output_cap: bool,
}

impl Refusal {
    fn body(message: &'static str) -> Self {
        Refusal {
            message: message.to_string(),
            output_cap: false,
        }
    }

    fn cap(message: String) -> Self {
        Refusal {
            message,
            output_cap: true,
        }
    }
}

/// The body fields that bound output tokens for a request path.
///
/// `/responses` (OpenAI Responses) and `/messages` (Anthropic) each have
/// exactly one such field. Every other path is treated as chat completions or
/// completions, which accept `max_completion_tokens`, `max_tokens`, or both.
fn output_token_fields(path: &str) -> &'static [&'static str] {
    if path.ends_with("/responses") {
        &["max_output_tokens"]
    } else if path.ends_with("/messages") {
        &["max_tokens"]
    } else {
        &["max_completion_tokens", "max_tokens"]
    }
}

/// Enforce the output-token cap against the body the provider will decode.
/// The body is only inspected, never rewritten: the client's output limit is
/// theirs to set, and the proxy refuses what exceeds the cap.
///
/// Refused: a limit above the cap, a limit that is not a non-negative integer,
/// and a repeated limit key (decoders disagree on which repeat wins, so any
/// repeat could hide a large value from the proxy).
///
/// A request that names no limit passes unchanged. This is the one place that
/// decides the absent case.
fn check_output_cap(path: &str, cap: u32, facts: &BodyDecodeFacts) -> Result<(), Refusal> {
    for field in output_token_fields(path) {
        let mut seen = facts.token_limits.iter().filter(|(name, _)| name == field);
        let Some((_, value)) = seen.next() else {
            // Absent: forwarded as the client sent it.
            continue;
        };
        if seen.next().is_some() {
            return Err(Refusal::cap(format!(
                "request body has duplicate `{field}` keys"
            )));
        }
        match value.as_u64() {
            Some(requested) if requested > u64::from(cap) => {
                return Err(Refusal::cap(format!(
                    "`{field}` {requested} exceeds the maximum of {cap} output tokens for this model"
                )));
            }
            Some(_) => {}
            None => {
                return Err(Refusal::cap(format!(
                    "`{field}` must be a non-negative integer"
                )));
            }
        }
    }
    Ok(())
}

/// Make the whole buffered body agree with the facts the proxy routed and
/// metered on (ADR-0004: decode is fully buffered), and enforce the output-token
/// cap against what the provider will decode.
///
/// `Ok(None)` forwards the body unchanged, `Ok(Some(_))` replaces it, and
/// `Err(_)` is a local 400. A non-JSON body is passed through unchanged unless
/// a routed model makes it an error, cap or no cap.
fn reconcile_request_body(
    body: &Bytes,
    requested_model: Option<&str>,
    force_include_usage: bool,
    max_output_tokens: Option<u32>,
    path: &str,
) -> Result<Option<Bytes>, Refusal> {
    if requested_model.is_none() && !force_include_usage && max_output_tokens.is_none() {
        return Ok(None);
    }
    let facts: BodyDecodeFacts = match serde_json::from_slice(body) {
        Ok(facts) => facts,
        // We routed on a model the body must therefore state; with no routed
        // model there is nothing to disagree with.
        Err(_) if requested_model.is_some() => {
            return Err(Refusal::body("request body is not a JSON object"))
        }
        Err(_) => return Ok(None),
    };
    if let Some(requested) = requested_model {
        // Upstream decoders disagree on first-vs-last for duplicate keys, so
        // a repeated `model` is refused rather than guessed at.
        if facts.duplicate_model {
            return Err(Refusal::body("request body has duplicate model keys"));
        }
        match facts.model.as_ref().and_then(serde_json::Value::as_str) {
            Some(model) if model == requested => {}
            _ => return Err(Refusal::body("request model disagrees with routed model")),
        }
    }
    if let Some(cap) = max_output_tokens {
        check_output_cap(path, cap, &facts)?;
    }
    if !(force_include_usage && facts.stream == Some(true) && !facts.include_usage) {
        return Ok(None);
    }
    // Deliberate: when the operator forces usage reporting, a client opt-out
    // does not switch metering off.
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Ok(None);
    };
    let Some(object) = value.as_object_mut() else {
        return Ok(None);
    };
    match object.get_mut("stream_options") {
        Some(serde_json::Value::Object(options)) => {
            options.insert("include_usage".to_string(), serde_json::Value::Bool(true));
        }
        _ => {
            object.insert(
                "stream_options".to_string(),
                serde_json::json!({"include_usage": true}),
            );
        }
    }
    serde_json::to_vec(&value)
        .map(|bytes| Some(Bytes::from(bytes)))
        .map_err(|_| Refusal::body("request body could not be serialized"))
}

/// Why the selected cluster's body preparation refused the request.
enum BodyRefusal {
    /// A `request_field_policy.deny` key is present.
    FieldNotPermitted(String),
    /// The body could not be rewritten (not JSON, not an object, model
    /// disagreement).
    Invalid(String),
}

/// Top-level keys present in a body that the cluster policy names. Only keys
/// the policy cares about are recorded; every value is skipped unparsed.
struct PolicyKeyScan {
    denied: Option<String>,
    strip_present: bool,
}

fn scan_policy_keys(
    policy: &proxy_config::ir::RequestFieldPolicy,
    body: &[u8],
) -> Result<PolicyKeyScan, String> {
    // Rust note: a `DeserializeSeed`-free way to walk a map is a hand-written
    // `Visitor`; `IgnoredAny` makes serde validate and discard each value
    // without building a `Value` tree.
    struct Scan<'a>(&'a proxy_config::ir::RequestFieldPolicy);
    impl<'de, 'a> serde::de::Visitor<'de> for Scan<'a> {
        type Value = PolicyKeyScan;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a JSON object")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            let mut scan = PolicyKeyScan {
                denied: None,
                strip_present: false,
            };
            // `Cow<str>` keys are unescaped, so `"mod\u0065ls"` matches `models`
            // exactly as the provider's decoder would see it.
            while let Some(key) = map.next_key::<std::borrow::Cow<'de, str>>()? {
                if scan.denied.is_none() && self.0.deny.iter().any(|d| d == key.as_ref()) {
                    scan.denied = Some(key.into_owned());
                } else if self.0.strip.iter().any(|d| d == key.as_ref()) {
                    scan.strip_present = true;
                }
                map.next_value::<serde::de::IgnoredAny>()?;
            }
            Ok(scan)
        }
    }
    use serde::Deserializer as _;
    let mut de = serde_json::Deserializer::from_slice(body);
    let scan = de
        .deserialize_map(Scan(policy))
        .map_err(|err| format!("request body is not a JSON object: {err}"))?;
    de.end()
        .map_err(|err| format!("request body is not valid JSON: {err}"))?;
    Ok(scan)
}

/// Build the body for the selected cluster: enforce its request-field policy
/// and apply its model rewrite. The model selected for routing remains in
/// `StreamInfo`; this changes only the bytes sent to the selected provider.
///
/// A policy-free cluster forwards the body untouched. With a policy, one key
/// scan decides; the body is parsed into a `Value` and reserialized only when
/// a key must be stripped or the model rewrite applies, and then once for both.
///
/// The body still names what the client sent (`requested_model`). The
/// cluster's mapping is looked up by the routing model, which is the
/// resolver's choice when one ran. A resolved model is written to the body
/// even without a mapping: otherwise the provider would receive the trigger
/// name (`auto`) rather than a model it serves.
fn prepare_attempt_body(
    runtime: Option<&proxy_config::ir::ProviderRuntimeConfig>,
    requested_model: Option<&str>,
    resolved_model: Option<&str>,
    body: &Bytes,
) -> Result<Bytes, BodyRefusal> {
    let policy = runtime
        .map(|runtime| &runtime.request_field_policy)
        .filter(|policy| !policy.is_empty());
    let upstream_model = requested_model.and_then(|requested| {
        let routing_model = resolved_model.unwrap_or(requested);
        runtime
            .and_then(|runtime| {
                runtime
                    .model_rewrites
                    .iter()
                    .find(|mapping| provider_model_pattern_matches(&mapping.pattern, routing_model))
                    .map(|mapping| mapping.upstream_model.as_str())
            })
            .or(resolved_model)
    });

    let mut must_strip = false;
    if let Some(policy) = policy {
        let scan = scan_policy_keys(policy, body).map_err(BodyRefusal::Invalid)?;
        if let Some(field) = scan.denied {
            return Err(BodyRefusal::FieldNotPermitted(field));
        }
        must_strip = scan.strip_present;
    }
    if !must_strip && upstream_model.is_none() {
        return Ok(body.clone());
    }

    let mut value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|err| BodyRefusal::Invalid(format!("request body is not valid JSON: {err}")))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| BodyRefusal::Invalid("request body must be a JSON object".to_string()))?;
    if must_strip {
        if let Some(policy) = policy {
            for field in &policy.strip {
                object.remove(field);
            }
        }
    }
    if let (Some(requested_model), Some(upstream_model)) = (requested_model, upstream_model) {
        match object.get("model").and_then(serde_json::Value::as_str) {
            Some(model) if model == requested_model => {}
            Some(_) => {
                return Err(BodyRefusal::Invalid(
                    "request model disagrees with routed model".to_string(),
                ))
            }
            None => {
                return Err(BodyRefusal::Invalid(
                    "request body has no model field".to_string(),
                ))
            }
        }
        object.insert(
            "model".to_string(),
            serde_json::Value::String(upstream_model.to_string()),
        );
    }
    serde_json::to_vec(&value)
        .map(Bytes::from)
        .map_err(|err| BodyRefusal::Invalid(format!("request body could not be serialized: {err}")))
}

fn path_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            use std::fmt::Write;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
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
pub(crate) fn apply_header_mutations(
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

/// S10.1: the single upgrade type this request is asking for, to gate
/// against `upgrade_configs` -- the first, lowercased token of the
/// `Upgrade` header, or `None` if there isn't one (no header, or an empty
/// value). RFC 9110 doesn't define `Upgrade` as a strict preference-ordered
/// list the way `Connection` is, but a real WebSocket client sends exactly
/// one token (`websocket`), and Envoy itself gates on a single configured
/// `upgrade_type` string per entry -- so "the first token" is what there is
/// to compare against `upgrade_allowed`.
fn requested_upgrade_type(headers: &http::HeaderMap) -> Option<String> {
    let value = headers.get(http::header::UPGRADE)?.to_str().ok()?;
    let first = value.split(',').next()?.trim();
    if first.is_empty() {
        return None;
    }
    Some(first.to_ascii_lowercase())
}

/// Synthesize a `DirectResponse` action's reply. File bodies are resolved
/// during config compilation; a file variant reaching this worker indicates
/// manually constructed IR outside the supported lowering path.
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
                "direct_response received an unresolved file-sourced body"
            );
            local_reply(
                StatusCode::INTERNAL_SERVER_ERROR,
                "direct_response file body was not loaded",
            )
        }
    }
}

/// Synthesize a `Redirect` action's reply (Envoy S1 redirect actions,
/// limited to `RedirectIR`'s four fields -- no scheme/port-only rewrite
/// variants). Builds `Location: <scheme>://<authority><path>` and returns it
/// with an empty body and `redirect.response_code` (already defaulted to
/// 301 at lowering).
fn redirect_response(redirect: &RedirectIR, head: &RequestHeaders) -> HttpResponseParts {
    // Rust note: Envoy forwards the *original downstream* scheme through a
    // redirect unless `https_redirect` forces it. We don't reliably have
    // that here -- h1 requests carry no scheme header, and this router
    // doesn't know the listener's TLS state -- so we default to "http"
    // whenever `https_redirect` is false. This under-serves an https
    // downstream connection redirected without `https_redirect` set (the
    // client would see an http Location); flagged rather than guessed at.
    let scheme = if redirect.https_redirect {
        "https"
    } else {
        "http"
    };

    // Same authority precedence `sync_route_head` (filter_manager.rs) uses
    // for route resolution (S1.1/S1.2): prefer the request's
    // `:authority`/absolute-form URI, fall back to the `Host` header.
    let host_header = head
        .headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok());
    let request_authority = head.uri.authority().map(|a| a.as_str()).or(host_header);

    let authority = match redirect.host_redirect.as_deref().or(request_authority) {
        Some(authority) => authority,
        None => return local_reply(StatusCode::BAD_REQUEST, "no host to redirect to"),
    };

    // `path_redirect` replaces the whole path (Envoy semantics: it is not a
    // prefix rewrite), so the original query string is dropped along with
    // the rest of the original path whenever it's set.
    let path = redirect
        .path_redirect
        .as_deref()
        .or_else(|| head.uri.path_and_query().map(|p| p.as_str()))
        .unwrap_or("/");

    let location = format!("{scheme}://{authority}{path}");
    let location_value = match HeaderValue::from_str(&location) {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(error = %err, location, "redirect Location is not a valid header value");
            return local_reply(StatusCode::BAD_REQUEST, "malformed redirect target");
        }
    };

    let status = StatusCode::from_u16(redirect.response_code).unwrap_or_else(|err| {
        tracing::warn!(
            error = %err,
            code = redirect.response_code,
            "RedirectIR::response_code failed StatusCode conversion after config-time validation, falling back to 301"
        );
        StatusCode::MOVED_PERMANENTLY
    });

    let mut resp = local_reply_with_status(status, Bytes::new());
    resp.head
        .headers
        .insert(http::header::LOCATION, location_value);
    resp.head
        .headers
        .insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    resp
}

/// What the credential step does for one attempt cluster (ADR-0007).
enum AttemptCredentials<'a> {
    /// Operator credential only: the request has no tenant credentials.
    Platform,
    /// Tenant mode: the cluster's slot and the tenant's secret for it.
    Tenant(&'a proxy_config::ir::TenantCredentialSlot, &'a TenantSecret),
}

/// Why a tenant-mode attempt cannot be given a credential. Both refusals are
/// final for the request: neither retries nor falls back to the operator
/// credential.
enum CredentialRefusal {
    /// The cluster has no slot, or the tenant holds nothing for its provider.
    /// Carries the slot's provider name when the cluster has one.
    Missing(Option<String>),
    /// The tenant holds a row for the provider that could not be decrypted.
    Unusable(String),
}

/// Decide, before anything is dialled, which credential an attempt cluster
/// gets. In tenant mode a cluster is never allowed to fall through to its
/// operator credential, even when the slot is absent (AGENTS.md invariant 6,
/// ADR-0007).
fn plan_attempt_credentials<'a>(
    tenant: Option<&'a TenantCredentialSet>,
    runtime: Option<&'a proxy_config::ir::ProviderRuntimeConfig>,
) -> Result<AttemptCredentials<'a>, CredentialRefusal> {
    let Some(set) = tenant else {
        return Ok(AttemptCredentials::Platform);
    };
    let Some(slot) = runtime.and_then(|runtime| runtime.tenant_credential.as_ref()) else {
        return Err(CredentialRefusal::Missing(None));
    };
    match set.get(&slot.provider) {
        Some(TenantCredential::Usable(secret)) => Ok(AttemptCredentials::Tenant(slot, secret)),
        Some(TenantCredential::Unusable) => Err(CredentialRefusal::Unusable(slot.provider.clone())),
        None => Err(CredentialRefusal::Missing(Some(slot.provider.clone()))),
    }
}

/// Final local reply for a refused tenant credential. Never names a secret.
fn credential_refusal_reply(
    info: &mut crate::StreamInfo,
    stats: &RouterStats,
    cluster: &str,
    refusal: &CredentialRefusal,
) -> HttpResponseParts {
    match refusal {
        CredentialRefusal::Missing(provider) => {
            stats.record_tenant_credential(
                provider
                    .as_deref()
                    .unwrap_or(instruments::TENANT_CREDENTIAL_NO_PROVIDER),
                instruments::TENANT_CREDENTIAL_MISSING,
            );
            tracing::warn!(cluster = %cluster, provider = ?provider, "tenant has no credential slot match for the selected cluster");
            info.response_code_details = Some("tenant_credential_missing".to_string());
            tenant_credential_missing_reply(provider.as_deref())
        }
        CredentialRefusal::Unusable(provider) => {
            stats.record_tenant_credential(provider, instruments::TENANT_CREDENTIAL_UNUSABLE);
            tracing::warn!(cluster = %cluster, provider = %provider, "tenant credential is unusable (decryption failed); failing closed");
            info.set_response_flag(ResponseFlag::UpstreamConnectionFailure);
            local_reply(
                StatusCode::SERVICE_UNAVAILABLE,
                "provider credential failure",
            )
        }
    }
}

/// `403` in the JSON error shape the config dialect's own local errors use
/// (`{"error":{"message":..,"type":..}}`).
fn tenant_credential_missing_reply(provider: Option<&str>) -> HttpResponseParts {
    let message = match provider {
        Some(provider) => format!("no tenant credential for provider {provider}"),
        None => "no tenant credential for any provider this route can use".to_string(),
    };
    let body = serde_json::json!({
        "error": { "message": message, "type": "tenant_credential_missing" }
    })
    .to_string();
    let mut resp = local_reply_with_status(StatusCode::FORBIDDEN, Bytes::from(body));
    resp.head.headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

/// Why [`select_host_for_request`] found no host.
enum NoHost {
    /// Nothing healthy to dial: `503 no healthy upstream`.
    Unhealthy,
    /// A host exists but the tenant has no credential for it: `403`. Carries
    /// the provider named by the first such cluster's slot, if it has one.
    Ineligible(Option<String>),
}

/// Run host selection. In tenant mode, distinguish "no eligible cluster" from
/// "nothing healthy": when the tenant-filtered pick finds nothing on the
/// first attempt, probe once without the filter. A host there means the
/// failure is eligibility, so `Err(Ineligible)`; otherwise `Err(Unhealthy)`.
fn select_host_for_request(
    entry: &dyn ClusterEntry,
    ctx: &mut LoadBalancerContext,
) -> Result<proxy_cluster::HostSelection, NoHost> {
    if let Some(sel) = entry.select_host(ctx) {
        return Ok(sel);
    }
    // On a retry the eligible members are exhausted, which is a health
    // outcome, so only the first pick is probed.
    if ctx.credential_providers.is_none() || !ctx.attempted_clusters.is_empty() {
        return Err(NoHost::Unhealthy);
    }
    let filter = ctx.credential_providers.take();
    let probe = entry.select_host(ctx);
    ctx.credential_providers = filter;
    Err(match probe {
        None => NoHost::Unhealthy,
        Some(sel) => NoHost::Ineligible(
            sel.member
                .as_ref()
                .and_then(|m| m.entry.provider_runtime())
                .and_then(|runtime| runtime.tenant_credential.as_ref())
                .map(|slot| slot.provider.clone()),
        ),
    })
}

/// A locally-synthesized error reply (no upstream involved) with a
/// plain-text body -- mirrors `stub::FixedResponseHandler`'s body
/// construction.
/// The local reply and response flag for a failed upstream send, as
/// Envoy's router answers a reset before response headers: `502` with `UPE`
/// only when the upstream broke the protocol, otherwise `503` with `UR` (an
/// explicit remote reset) or `UC` (the connection closed or failed). The
/// `503` matches the `PoolError::ResetBeforeHeaders` arm, which also flags
/// `UR`.
fn codec_error_reply(
    err: &crate::codec::UpstreamCodecError,
    dcb: &mut dyn DecoderCallbacks,
) -> HttpResponseParts {
    let (flag, status) = if crate::codec::is_remote_reset(err) {
        (
            ResponseFlag::UpstreamRemoteReset,
            StatusCode::SERVICE_UNAVAILABLE,
        )
    } else if crate::codec::is_protocol_error(err) {
        (ResponseFlag::UpstreamProtocolError, StatusCode::BAD_GATEWAY)
    } else {
        (
            ResponseFlag::UpstreamConnectionTermination,
            StatusCode::SERVICE_UNAVAILABLE,
        )
    };
    dcb.stream_info().set_response_flag(flag);
    local_reply(status, "upstream connection failure")
}

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
        upgrade: None,
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

    /// The S6 classification the router applies to each attempt before
    /// feeding the outlier detector. A silently-wrong arm here would eject (or
    /// fail to eject) on the wrong signal, so it is pinned directly.
    #[test]
    fn outlier_result_for_maps_every_outcome() {
        use AttemptOutcome::*;
        // 502/503/504 are gateway failures (also bump the 5xx detector).
        assert_eq!(
            outlier_result_for(&Response(502)),
            Some(RequestResult::GatewayFailure)
        );
        assert_eq!(
            outlier_result_for(&Response(503)),
            Some(RequestResult::GatewayFailure)
        );
        assert_eq!(
            outlier_result_for(&Response(504)),
            Some(RequestResult::GatewayFailure)
        );
        // Other 5xx are plain 5xx.
        assert_eq!(
            outlier_result_for(&Response(500)),
            Some(RequestResult::Http5xx)
        );
        assert_eq!(
            outlier_result_for(&Response(501)),
            Some(RequestResult::Http5xx)
        );
        assert_eq!(
            outlier_result_for(&Response(599)),
            Some(RequestResult::Http5xx)
        );
        // Anything below 500 is a success as far as host health goes -- a 4xx
        // is the client's fault, not the host's.
        assert_eq!(
            outlier_result_for(&Response(200)),
            Some(RequestResult::Success)
        );
        assert_eq!(
            outlier_result_for(&Response(404)),
            Some(RequestResult::Success)
        );
        assert_eq!(
            outlier_result_for(&Response(429)),
            Some(RequestResult::Success)
        );
        // Connection-level failures fold into the local-origin bucket.
        for o in [
            ConnectFailure,
            ResetBeforeHeaders,
            ResetAfterHeaders,
            RefusedStream,
            PerTryTimeout,
        ] {
            assert_eq!(
                outlier_result_for(&o),
                Some(RequestResult::LocalOriginFailure),
                "{o:?}"
            );
        }
        // A circuit-breaker overflow never reached the host -> not reported.
        assert_eq!(outlier_result_for(&PoolOverflow), None);
    }

    use crate::filter::{FilterInstanceFactory, RequestHeaders};
    use crate::filter_manager::FilterChainHandler;
    use crate::handler::{DownstreamInfo, StreamHandler};
    use crate::stat_handles::StatHandles;
    use proxy_observability::stats::{StatsControl, WorkerId};

    /// A fresh, single-worker [`RouterStats`] resolved
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
    /// counts how many it has accepted -- what the h2
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
    /// connections it has accepted, and every response carries `Connection:
    /// close` -- what `connection_close_response_is_not_reused` asserts
    /// against to prove the h1 cache honors an explicit
    /// `Connection: close` and never reuses that connection.
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

    /// Like [`spawn_counting_h1_upstream`], but genuinely keep-alive
    /// capable: each accepted connection is served in a loop that reads and
    /// answers as many bodyless-GET requests as arrive on it (no
    /// `Connection: close`, plain HTTP/1.1 -- persistent by default), rather
    /// than closing after one. What the h1 reuse tests
    /// (`reuse_across_two_requests_opens_one_connection`,
    /// `truncated_or_errored_response_is_not_reused`) assert against: with a
    /// peer willing to stay open, whether a SECOND request opens a new
    /// connection or not is entirely down to `H1ConnCache`'s own reuse
    /// decision, not anything the peer forced.
    async fn spawn_counting_h1_keepalive_upstream(
    ) -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
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
                    loop {
                        let mut request_buf = Vec::new();
                        let mut chunk = [0u8; 1024];
                        loop {
                            let n = match stream.read(&mut chunk).await {
                                Ok(0) | Err(_) => return, // peer closed
                                Ok(n) => n,
                            };
                            request_buf.extend_from_slice(&chunk[..n]);
                            // These test requests are always bodyless GETs,
                            // so the header terminator is also the end of
                            // the whole request.
                            if request_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        if stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                            .await
                            .is_err()
                        {
                            return;
                        }
                        // Loop back for the NEXT request on this same
                        // connection -- what makes this mock actually
                        // keep-alive, unlike `spawn_counting_h1_upstream`'s
                        // one-shot-per-connection task.
                    }
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
    /// for the tests that need to assert on recorded
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
                // Non-EDS fixture: hosts come from `endpoints`/`discovery`.
                eds: None,
                name: "up".to_string(),
                discovery: DiscoveryType::Static,
                lb_policy: LbPolicy::RoundRobin,
                connect_timeout: Duration::from_secs(5),
                endpoints: vec![EndpointIR {
                    metadata: Default::default(),
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
                request_path_rewrite: None,
                provider_runtime: None,
                usage_dialect: None,
                health_check: None,
                outlier_detection: None,
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
                    streaming_strict: false,
                    typed_per_filter_config: BTreeMap::new(),
                    route_index: 0,
                    include_request_attempt_count: false,
                    include_attempt_count_in_response: false,
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
    /// HTTP/2 -- lets the h2 connection-reuse tests exercise the
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
                // Non-EDS fixture: hosts come from `endpoints`/`discovery`.
                eds: None,
                name: "up".to_string(),
                discovery: DiscoveryType::Static,
                lb_policy: LbPolicy::RoundRobin,
                connect_timeout: Duration::from_secs(5),
                endpoints: vec![EndpointIR {
                    metadata: Default::default(),
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
                request_path_rewrite: None,
                provider_runtime: None,
                usage_dialect: None,
                health_check: None,
                outlier_detection: None,
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
                    streaming_strict: false,
                    typed_per_filter_config: BTreeMap::new(),
                    route_index: 0,
                    include_request_attempt_count: false,
                    include_attempt_count_in_response: false,
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
            on_upgrade: None,
        }
    }

    // Rust note: `send_upstream_http1` (like the downstream h1 codec) uses
    // hyper's client, which spawns non-`Send` per-connection driver tasks via
    // `tokio::task::spawn_local` -- so every test that reaches it needs a
    // `LocalSet` running on a `current_thread` runtime, exactly like
    // `tests/http1_upstream_codec.rs`.

    #[test]
    fn cluster_path_rewrite_replaces_v1_and_query() {
        let mut head = RequestHeaders {
            method: Method::POST,
            uri: Uri::from_static("/v1/chat/completions?client=ignored"),
            headers: HeaderMap::new(),
        };
        let rewrite = proxy_config::ir::RequestPathRewrite {
            match_prefix: "/v1".to_string(),
            replacement_prefix: "/openai/deployments/deployment-a".to_string(),
            query: Some("api-version=2024-10-21".to_string()),
        };

        apply_cluster_request_path_rewrite(Some(&rewrite), &mut head);

        assert_eq!(
            head.uri,
            "/openai/deployments/deployment-a/chat/completions?api-version=2024-10-21"
        );
    }

    #[test]
    fn provider_path_template_uses_cluster_model_mapping() {
        let mut head = RequestHeaders {
            method: Method::POST,
            uri: Uri::from_static("/v1/messages?trace=1"),
            headers: HeaderMap::new(),
        };
        let template = proxy_config::ir::ProviderPathTemplate::Vertex {
            project: "project-a".to_string(),
            location: "us-central1".to_string(),
            publisher: "anthropic".to_string(),
            models: vec![proxy_config::ir::ProviderModelRewrite {
                pattern: "claude-*".to_string(),
                upstream_model: "claude-sonnet@20250929".to_string(),
            }],
        };

        apply_cluster_provider_path_template(Some(&template), Some("claude-sonnet"), &mut head);

        assert_eq!(
            head.uri,
            "/v1/projects/project-a/locations/us-central1/publishers/anthropic/models/claude-sonnet%4020250929:streamRawPredict?trace=1"
        );
    }

    fn reconcile(
        body: &'static str,
        model: Option<&str>,
        force: bool,
    ) -> Result<Option<Bytes>, String> {
        reconcile_request_body(
            &Bytes::from_static(body.as_bytes()),
            model,
            force,
            None,
            "/v1/chat/completions",
        )
        .map_err(|r| r.message)
    }

    /// Run the reconcile step with an output-token cap on `path`.
    fn reconcile_capped(
        body: &'static str,
        path: &str,
        model: Option<&str>,
        cap: u32,
    ) -> Result<Option<Bytes>, Refusal> {
        reconcile_request_body(
            &Bytes::from_static(body.as_bytes()),
            model,
            false,
            Some(cap),
            path,
        )
    }

    const CHAT: &str = "/v1/chat/completions";

    fn refused_message(body: &'static str, path: &str) -> String {
        let refusal = reconcile_capped(body, path, None, 100).expect_err(body);
        assert!(refusal.output_cap, "{body}: must count as a cap refusal");
        refusal.message
    }

    #[test]
    fn cap_refuses_a_larger_limit_naming_the_field_and_the_cap() {
        let msg = refused_message(r#"{"max_tokens":9000}"#, CHAT);
        assert!(msg.contains("max_tokens") && msg.contains("100"), "{msg}");
        let msg = refused_message(r#"{"max_completion_tokens":101}"#, CHAT);
        assert!(msg.contains("max_completion_tokens"), "{msg}");
        // Either chat field over the cap is enough.
        refused_message(r#"{"max_tokens":5,"max_completion_tokens":500}"#, CHAT);
    }

    #[test]
    fn cap_uses_the_field_the_path_names() {
        let msg = refused_message(r#"{"max_output_tokens":900}"#, "/v1/responses");
        assert!(msg.contains("max_output_tokens"), "{msg}");
        let msg = refused_message(r#"{"max_tokens":900}"#, "/v1/messages");
        assert!(msg.contains("max_tokens"), "{msg}");
        // Another path's field is not this path's limit.
        assert_eq!(
            reconcile_capped(r#"{"max_tokens":9000}"#, "/v1/responses", None, 100).unwrap(),
            None
        );
        assert_eq!(
            reconcile_capped(r#"{"max_output_tokens":9000}"#, "/v1/messages", None, 100).unwrap(),
            None
        );
    }

    #[test]
    fn cap_never_changes_the_body() {
        for (path, body) in [
            (CHAT, r#"{"model":"m"}"#),
            (CHAT, r#"{ "max_tokens" : 100 }"#),
            (CHAT, r#"{"max_tokens":0}"#),
            ("/v1/responses", r#"{"input":"hi"}"#),
            ("/v1/messages", r#"{"max_tokens":7}"#),
        ] {
            assert_eq!(
                reconcile_capped(body, path, None, 100).unwrap(),
                None,
                "{body}"
            );
        }
    }

    #[test]
    fn cap_refuses_duplicate_limit_keys_plain_or_escaped() {
        for body in [
            r#"{"max_tokens":1,"max_tokens":999999}"#,
            r#"{"max_tokens":999999,"max_tokens":1}"#,
            r#"{"max_tokens":1,"max_\u0074okens":999999}"#,
        ] {
            let msg = refused_message(body, CHAT);
            assert!(msg.contains("duplicate"), "{body}: {msg}");
        }
        refused_message(
            r#"{"max_output_tokens":1,"max_output_tokens":2}"#,
            "/v1/responses",
        );
    }

    #[test]
    fn cap_recognizes_an_escaped_key_as_the_limit() {
        // `\u006dax_tokens` decodes to `max_tokens`, as the provider sees it.
        let msg = refused_message(r#"{"\u006dax_tokens":9000}"#, CHAT);
        assert!(msg.contains("exceeds"), "{msg}");
    }

    #[test]
    fn cap_refuses_a_limit_that_is_not_a_non_negative_integer() {
        for bad in ["-1", "1.5", "1e3", "\"100\"", "null", "true", "[]"] {
            let body: &'static str =
                Box::leak(format!(r#"{{"max_tokens":{bad}}}"#).into_boxed_str());
            let msg = refused_message(body, CHAT);
            assert!(msg.contains("non-negative integer"), "{bad}: {msg}");
        }
    }

    #[test]
    fn cap_still_checks_the_routed_model() {
        let refusal = reconcile_capped(r#"{"model":"other"}"#, CHAT, Some("cheap"), 100)
            .expect_err("model mismatch");
        assert!(!refusal.output_cap, "a model refusal is not a cap refusal");
        assert!(reconcile_capped(
            r#"{"model":"cheap","model":"cheap"}"#,
            CHAT,
            Some("cheap"),
            100
        )
        .is_err());
        assert_eq!(
            reconcile_capped(r#"{"model":"cheap"}"#, CHAT, Some("cheap"), 100).unwrap(),
            None
        );
    }

    #[test]
    fn cap_with_a_non_json_body_follows_the_model_check() {
        assert_eq!(reconcile_capped("not json", CHAT, None, 100).unwrap(), None);
        assert!(reconcile_capped("not json", CHAT, Some("cheap"), 100).is_err());
    }

    #[test]
    fn cap_check_and_forced_usage_coexist() {
        let body = Bytes::from_static(br#"{"stream":true,"max_tokens":50}"#);
        let rewritten = reconcile_request_body(&body, None, true, Some(100), CHAT)
            .unwrap()
            .expect("usage is still forced");
        let value: serde_json::Value = serde_json::from_slice(&rewritten).unwrap();
        assert_eq!(value["max_tokens"], 50);
        assert_eq!(value["stream_options"]["include_usage"], true);
        let over = Bytes::from_static(br#"{"stream":true,"max_tokens":500}"#);
        assert!(reconcile_request_body(&over, None, true, Some(100), CHAT).is_err());
    }

    #[test]
    fn reconcile_refuses_escaped_and_plain_duplicate_models() {
        assert!(reconcile(
            r#"{"model":"cheap","mod\u0065l":"expensive"}"#,
            Some("cheap"),
            false
        )
        .is_err());
        assert!(reconcile(r#"{"model":"cheap","model":"cheap"}"#, Some("cheap"), false).is_err());
    }

    #[test]
    fn reconcile_refuses_a_body_model_that_differs_from_the_routed_model() {
        assert!(reconcile(r#"{"model":"expensive"}"#, Some("cheap"), false).is_err());
        assert!(reconcile(r#"{"messages":[]}"#, Some("cheap"), false).is_err());
        assert!(reconcile("not json", Some("cheap"), false).is_err());
    }

    #[test]
    fn reconcile_leaves_agreeing_and_unrouted_bodies_alone() {
        assert_eq!(
            reconcile(r#"{"model":"cheap","stream":true}"#, Some("cheap"), false),
            Ok(None)
        );
        assert_eq!(reconcile("not json", None, false), Ok(None));
        assert_eq!(reconcile("not json", None, true), Ok(None));
    }

    #[test]
    fn reconcile_forces_usage_over_a_client_opt_out_and_keeps_other_options() {
        let rewritten = reconcile(
            r#"{"stream":true,"stream_options":{"include_usage":false,"x":1}}"#,
            None,
            true,
        )
        .unwrap()
        .expect("opt-out must be overridden");
        let value: serde_json::Value = serde_json::from_slice(&rewritten).unwrap();
        assert_eq!(value["stream_options"]["include_usage"], true);
        assert_eq!(value["stream_options"]["x"], 1);
    }

    #[test]
    fn reconcile_uses_the_last_stream_options_when_duplicated() {
        let rewritten = reconcile(
            r#"{"stream":true,"stream_options":{"include_usage":true},"stream_options":{"include_usage":false}}"#,
            None,
            true,
        )
        .unwrap()
        .expect("last stream_options opts out");
        let value: serde_json::Value = serde_json::from_slice(&rewritten).unwrap();
        assert_eq!(value["stream_options"]["include_usage"], true);
        // The mirror case needs no rewrite.
        assert_eq!(
            reconcile(
                r#"{"stream":true,"stream_options":{"include_usage":false},"stream_options":{"include_usage":true}}"#,
                None,
                true
            ),
            Ok(None)
        );
    }

    #[test]
    fn reconcile_does_not_touch_usage_unless_forced_or_streaming() {
        let opt_out = r#"{"stream":true,"stream_options":{"include_usage":false}}"#;
        assert_eq!(reconcile(opt_out, None, false), Ok(None));
        assert_eq!(reconcile(r#"{"stream":false}"#, None, true), Ok(None));
    }

    #[test]
    fn selected_provider_model_rewrite_changes_only_the_upstream_body() {
        let runtime = runtime_with(
            vec![proxy_config::ir::ProviderModelRewrite {
                pattern: "fast-*".to_string(),
                upstream_model: "provider-fast-v2".to_string(),
            }],
            Default::default(),
        );
        let body = Bytes::from_static(
            br#"{"model":"fast-alias","messages":[{"role":"user","content":"hi"}]}"#,
        );

        let rewritten = prepare_attempt_body(Some(&runtime), Some("fast-alias"), None, &body)
            .unwrap_or_else(|_| panic!("selected provider model rewrite must succeed"));

        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&rewritten).unwrap()["model"],
            "provider-fast-v2"
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&rewritten).unwrap()["messages"][0]
                ["content"],
            "hi"
        );
    }

    #[test]
    fn provider_model_rewrite_requires_the_body_to_match_the_routed_model() {
        let runtime = runtime_with(
            vec![proxy_config::ir::ProviderModelRewrite {
                pattern: "fast-*".to_string(),
                upstream_model: "provider-fast-v2".to_string(),
            }],
            Default::default(),
        );

        let Err(BodyRefusal::Invalid(err)) = prepare_attempt_body(
            Some(&runtime),
            Some("fast-alias"),
            None,
            &Bytes::from_static(br#"{"model":"client-spoofed"}"#),
        ) else {
            panic!("a rewrite cannot turn an unverified body into an upstream request");
        };

        assert!(err.contains("disagrees"), "unexpected error: {err}");
    }

    fn runtime_with(
        model_rewrites: Vec<proxy_config::ir::ProviderModelRewrite>,
        request_field_policy: proxy_config::ir::RequestFieldPolicy,
    ) -> proxy_config::ir::ProviderRuntimeConfig {
        proxy_config::ir::ProviderRuntimeConfig {
            credential: None,
            path_template: None,
            model_rewrites,
            request_field_policy,
            tenant_credential: None,
        }
    }

    fn policy(deny: &[&str], strip: &[&str]) -> proxy_config::ir::RequestFieldPolicy {
        proxy_config::ir::RequestFieldPolicy {
            deny: deny.iter().map(|s| s.to_string()).collect(),
            strip: strip.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn prepare(
        runtime: &proxy_config::ir::ProviderRuntimeConfig,
        model: Option<&str>,
        body: &'static str,
    ) -> Result<Bytes, BodyRefusal> {
        prepare_attempt_body(
            Some(runtime),
            model,
            None,
            &Bytes::from_static(body.as_bytes()),
        )
    }

    #[test]
    fn deny_refuses_a_listed_top_level_key_and_names_it() {
        let runtime = runtime_with(Vec::new(), policy(&["models"], &[]));
        let Err(BodyRefusal::FieldNotPermitted(field)) =
            prepare(&runtime, None, r#"{"model":"a","models":["a","b"]}"#)
        else {
            panic!("expected a denial");
        };
        assert_eq!(field, "models");
    }

    #[test]
    fn deny_compares_keys_after_json_unescaping() {
        let runtime = runtime_with(Vec::new(), policy(&["models"], &[]));
        assert!(matches!(
            prepare(&runtime, None, r#"{"mod\u0065ls":["b"]}"#),
            Err(BodyRefusal::FieldNotPermitted(_))
        ));
    }

    #[test]
    fn deny_looks_at_top_level_keys_only() {
        let runtime = runtime_with(Vec::new(), policy(&["models"], &[]));
        let body = r#"{"model":"a","metadata":{"models":["b"]}}"#;
        let out = prepare(&runtime, None, body).unwrap_or_else(|_| panic!("nested key allowed"));
        assert_eq!(&out[..], body.as_bytes());
    }

    #[test]
    fn policy_with_a_non_object_body_is_refused() {
        let runtime = runtime_with(Vec::new(), policy(&["models"], &[]));
        for body in ["[1]", "not json", r#"{"a":1} trailing"#] {
            assert!(
                matches!(prepare(&runtime, None, body), Err(BodyRefusal::Invalid(_))),
                "{body}"
            );
        }
    }

    #[test]
    fn empty_policy_does_not_parse_or_touch_the_body() {
        let runtime = runtime_with(Vec::new(), Default::default());
        let out = prepare(&runtime, None, "not json at all").unwrap_or_else(|_| panic!("no-op"));
        assert_eq!(&out[..], b"not json at all");
    }

    #[test]
    fn strip_removes_only_the_named_key() {
        let runtime = runtime_with(Vec::new(), policy(&[], &["plugins"]));
        let out = prepare(
            &runtime,
            None,
            r#"{"model":"a","plugins":[{"id":"web"}],"messages":[1]}"#,
        )
        .unwrap_or_else(|_| panic!("strip must succeed"));
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(value, serde_json::json!({"model":"a","messages":[1]}));
    }

    #[test]
    fn strip_with_the_key_absent_forwards_the_exact_bytes() {
        let runtime = runtime_with(Vec::new(), policy(&[], &["plugins"]));
        let body = "{ \"model\" :  \"a\" }";
        let out = prepare(&runtime, None, body).unwrap_or_else(|_| panic!("ok"));
        assert_eq!(&out[..], body.as_bytes());
    }

    #[test]
    fn strip_and_model_rewrite_apply_in_one_pass() {
        let runtime = runtime_with(
            vec![proxy_config::ir::ProviderModelRewrite {
                pattern: "fast-*".to_string(),
                upstream_model: "up".to_string(),
            }],
            policy(&[], &["plugins"]),
        );
        let out = prepare(
            &runtime,
            Some("fast-x"),
            r#"{"model":"fast-x","plugins":[1]}"#,
        )
        .unwrap_or_else(|_| panic!("ok"));
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(value, serde_json::json!({"model":"up"}));
    }

    #[test]
    fn deny_wins_over_a_model_rewrite() {
        let runtime = runtime_with(
            vec![proxy_config::ir::ProviderModelRewrite {
                pattern: "*".to_string(),
                upstream_model: "up".to_string(),
            }],
            policy(&["route"], &[]),
        );
        assert!(matches!(
            prepare(&runtime, Some("m"), r#"{"model":"m","route":"x"}"#),
            Err(BodyRefusal::FieldNotPermitted(_))
        ));
    }

    #[test]
    fn resolved_model_reaches_an_unmapped_provider_instead_of_the_trigger() {
        let body = Bytes::from_static(br#"{"model":"auto","stream":true}"#);

        let rewritten = prepare_attempt_body(None, Some("auto"), Some("fast"), &body)
            .unwrap_or_else(|_| panic!("a resolved model must be written to the body"));

        let value = serde_json::from_slice::<serde_json::Value>(&rewritten).unwrap();
        assert_eq!(value["model"], "fast");
        assert_eq!(value["stream"], true);
    }

    #[test]
    fn resolved_model_is_mapped_through_the_cluster_rewrites() {
        let runtime = runtime_with(
            vec![
                proxy_config::ir::ProviderModelRewrite {
                    pattern: "auto".to_string(),
                    upstream_model: "provider-wrong".to_string(),
                },
                proxy_config::ir::ProviderModelRewrite {
                    pattern: "fast".to_string(),
                    upstream_model: "provider-fast-v2".to_string(),
                },
            ],
            Default::default(),
        );
        let body = Bytes::from_static(br#"{"model":"auto"}"#);

        let rewritten = prepare_attempt_body(Some(&runtime), Some("auto"), Some("fast"), &body)
            .unwrap_or_else(|_| panic!("a resolved model must be mapped by the selected cluster"));

        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&rewritten).unwrap()["model"],
            "provider-fast-v2"
        );
    }

    #[test]
    fn resolved_rewrite_still_requires_the_body_to_match_the_requested_model() {
        let Err(BodyRefusal::Invalid(err)) = prepare_attempt_body(
            None,
            Some("auto"),
            Some("fast"),
            &Bytes::from_static(br#"{"model":"client-spoofed"}"#),
        ) else {
            panic!("the body must still name what the resolver saw");
        };

        assert!(err.contains("disagrees"), "unexpected error: {err}");
    }

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

    /// The S5 circuit breaker rejects the second attempt
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

    /// A served request's `upstream_rq_time` observation
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

    /// `ClusterManager` (routing/dialing) knows about
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
                streaming_strict: false,
                typed_per_filter_config: BTreeMap::new(),
                route_index: 0,
                include_request_attempt_count: false,
                include_attempt_count_in_response: false,
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

    // ---------------------------------------------------- redirects --

    /// Two `Redirect` routes, distinguished by prefix: `/foo` forces https
    /// and preserves the request's host+path (`RedirectIR::host_redirect`/
    /// `path_redirect` both `None`); `/rewrite` replaces both host and path
    /// literally. Mirrors [`direct_response_route_table`]'s shape.
    fn redirect_route_table() -> RouteTable {
        fn route(prefix: &str, redirect: RedirectIR) -> Arc<RouteEntry> {
            Arc::new(RouteEntry {
                name: None,
                matcher: prefix_matcher(prefix),
                action: RouteActionIR::Redirect(redirect),
                request_headers_to_add: Vec::new(),
                streaming_strict: false,
                typed_per_filter_config: BTreeMap::new(),
                route_index: 0,
                include_request_attempt_count: false,
                include_attempt_count_in_response: false,
            })
        }
        RouteTable::new(
            "test-routes".to_string(),
            vec![VirtualHostIR {
                name: "vh".to_string(),
                domains: vec!["*".to_string()],
                routes: vec![
                    route(
                        "/foo",
                        RedirectIR {
                            host_redirect: None,
                            path_redirect: None,
                            https_redirect: true,
                            response_code: 301,
                        },
                    ),
                    route(
                        "/rewrite",
                        RedirectIR {
                            host_redirect: Some("new.example.com".to_string()),
                            path_redirect: Some("/bar".to_string()),
                            https_redirect: false,
                            response_code: 302,
                        },
                    ),
                ],
                typed_per_filter_config: BTreeMap::new(),
            }],
            BTreeMap::new(),
        )
        .expect("two non-overlapping prefixes on one domain is a valid table")
    }

    /// Like [`request`], but with a caller-chosen `Host` header -- the
    /// redirect tests below need `example.com` rather than `request`'s
    /// hardcoded `test.local` so the expected `Location` reads naturally.
    fn request_with_host(path: &'static str, host: &'static str) -> HttpRequestParts {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::HOST, HeaderValue::from_str(host).unwrap());
        HttpRequestParts {
            head: RequestHeaders {
                method: Method::GET,
                uri: Uri::from_static(path),
                headers,
            },
            on_upgrade: None,
            body: local_boxed(
                Full::new(Bytes::new())
                    .map_err(|infallible: std::convert::Infallible| match infallible {}),
            ),
            downstream: DownstreamInfo::loopback(),
        }
    }

    fn redirect_handler() -> FilterChainHandler {
        let route_table = redirect_route_table();
        let manager = ClusterManager::with_default_transport(Arc::new(FakeResolver::new()));
        let terminal_factory: Arc<dyn TerminalFilterInstanceFactory> = Arc::new(
            RouterFilterFactory::new(Arc::new(manager), test_router_stats(&[])),
        );
        FilterChainHandler::new(
            vec![],
            terminal_factory,
            Arc::new(route_table),
            false,
            false,
            0,
        )
    }

    /// `https_redirect: true` with no `host_redirect`/`path_redirect`: the
    /// scheme is forced to https, but the request's own host and full path
    /// (including query) ride through unchanged -- Envoy S1's "redirect to
    /// https" case.
    #[tokio::test(flavor = "current_thread")]
    async fn redirect_https_redirect_forces_scheme_and_preserves_host_and_path() {
        LocalSet::new()
            .run_until(async {
                let handler = redirect_handler();
                let resp = handler
                    .handle(request_with_host("/foo?x=1", "example.com"))
                    .await;

                assert_eq!(
                    resp.head.status.as_u16(),
                    301,
                    "RedirectIR default response_code"
                );
                assert_eq!(
                    resp.head.headers.get(http::header::LOCATION).unwrap(),
                    "https://example.com/foo?x=1"
                );
                assert_eq!(
                    resp.head.headers.get(http::header::CONTENT_LENGTH).unwrap(),
                    "0"
                );
                let body = resp.body.collect().await.unwrap().to_bytes();
                assert!(body.is_empty(), "redirect body must be empty, got {body:?}");
            })
            .await;
    }

    /// `host_redirect` + `path_redirect` both set: both are used literally,
    /// `path_redirect` replaces the WHOLE path (Envoy semantics -- not a
    /// prefix rewrite), so the original query string is dropped along with
    /// the rest of the original path.
    #[tokio::test(flavor = "current_thread")]
    async fn redirect_host_and_path_redirect_replace_the_whole_target() {
        LocalSet::new()
            .run_until(async {
                let handler = redirect_handler();
                let resp = handler
                    .handle(request_with_host("/rewrite?ignored=1", "example.com"))
                    .await;

                assert_eq!(resp.head.status.as_u16(), 302);
                assert_eq!(
                    resp.head.headers.get(http::header::LOCATION).unwrap(),
                    "http://new.example.com/bar",
                    "path_redirect replaces the whole path -- the original \
                     query string must not survive"
                );
                assert_eq!(
                    resp.head.headers.get(http::header::CONTENT_LENGTH).unwrap(),
                    "0"
                );
                let body = resp.body.collect().await.unwrap().to_bytes();
                assert!(body.is_empty(), "redirect body must be empty, got {body:?}");
            })
            .await;
    }

    // ------------------------------------------------- h2 reuse --

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
                        // Atomically claim one refusal without decrementing zero.
                        // compare_exchange_weak also works on the declared MSRV.
                        let mut count = remaining.load(Ordering::SeqCst);
                        let refuse = loop {
                            if count == 0 {
                                break false;
                            }
                            match remaining.compare_exchange_weak(
                                count,
                                count - 1,
                                Ordering::SeqCst,
                                Ordering::SeqCst,
                            ) {
                                Ok(_) => break true,
                                Err(observed) => count = observed,
                            }
                        };
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
            hedge_on_per_try_timeout: false,
            retriable_status_codes: Vec::new(),
            retry_back_off: proxy_config::ir::RetryBackOff {
                base_interval: Duration::from_millis(1),
                max_interval: Duration::from_millis(2),
            },
            host_selection_retry_max_attempts: 1,
            avoid_previous_hosts: false,
        }
    }

    /// `retry_on: refused-stream` end to end, on a real RST_STREAM.
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

    /// The h1 cache's own core proof: two SEQUENTIAL requests against a
    /// keep-alive-capable h1 upstream must open exactly ONE TCP connection --
    /// the second request reuses the first, rather than dialing fresh. Must
    /// FAIL if reuse is removed (i.e. reverts to two accepts).
    #[tokio::test(flavor = "current_thread")]
    async fn reuse_across_two_requests_opens_one_connection() {
        LocalSet::new()
            .run_until(async {
                let (addr, accepted) = spawn_counting_h1_keepalive_upstream().await;
                let router =
                    build_router(addr, prefix_matcher("/"), forward_to_up(None, None, None)).await;

                let resp1 = router.handle(request("/")).await;
                assert_eq!(resp1.head.status, StatusCode::OK);
                // Drain to a clean EOF -- the ONE thing that makes this
                // connection eligible to go back into `H1ConnCache` at all
                // (see `H1ReuseBody`'s doc).
                resp1
                    .body
                    .collect()
                    .await
                    .expect("first response body drains cleanly");

                let resp2 = router.handle(request("/")).await;
                assert_eq!(resp2.head.status, StatusCode::OK);
                resp2
                    .body
                    .collect()
                    .await
                    .expect("second response body drains cleanly");

                assert_eq!(
                    accepted.load(std::sync::atomic::Ordering::SeqCst),
                    1,
                    "a second request against a keep-alive-capable upstream must reuse the \
                     first connection, not open a new one"
                );
            })
            .await;
    }

    /// The conservative guard, checked directly: a response that explicitly
    /// asks for `Connection: close` must never be handed back to the next
    /// request, even against an otherwise ordinary upstream.
    /// `build_router`'s default cluster is h1 (see `build_router_h2` for the
    /// h2 variant of these helpers).
    #[tokio::test(flavor = "current_thread")]
    async fn connection_close_response_is_not_reused() {
        LocalSet::new()
            .run_until(async {
                let (addr, accepted) = spawn_counting_h1_upstream().await;
                let router =
                    build_router(addr, prefix_matcher("/"), forward_to_up(None, None, None)).await;

                let resp1 = router.handle(request("/")).await;
                assert_eq!(resp1.head.status, StatusCode::OK);
                resp1
                    .body
                    .collect()
                    .await
                    .expect("first response body drains cleanly");

                let resp2 = router.handle(request("/")).await;
                assert_eq!(resp2.head.status, StatusCode::OK);
                resp2
                    .body
                    .collect()
                    .await
                    .expect("second response body drains cleanly");

                assert_eq!(
                    accepted.load(std::sync::atomic::Ordering::SeqCst),
                    2,
                    "a `Connection: close` response must never be reused, even though it was \
                     drained cleanly"
                );
            })
            .await;
    }

    /// The other conservative guard: a response whose body was NOT fully
    /// consumed before the next request went out (a truncated read, a
    /// client that hung up, an idle timeout giving up early -- all look the
    /// same from this cache's point of view: the body was dropped before
    /// reaching a clean EOF) must never be reused either, even against a
    /// upstream that is itself perfectly willing to keep the connection
    /// open. Proves a not-cleanly-finished connection never returns to the
    /// pool.
    #[tokio::test(flavor = "current_thread")]
    async fn truncated_or_errored_response_is_not_reused() {
        LocalSet::new()
            .run_until(async {
                let (addr, accepted) = spawn_counting_h1_keepalive_upstream().await;
                let router =
                    build_router(addr, prefix_matcher("/"), forward_to_up(None, None, None)).await;

                let resp1 = router.handle(request("/")).await;
                assert_eq!(resp1.head.status, StatusCode::OK);
                // Deliberately drop the body WITHOUT draining it to EOF --
                // `H1ReuseBody::completed` never gets set, so its `Drop`
                // must discard the connection rather than risk handing the
                // next request a connection whose peer may still be
                // mid-write of THIS response.
                drop(resp1.body);

                let resp2 = router.handle(request("/")).await;
                assert_eq!(resp2.head.status, StatusCode::OK);
                resp2
                    .body
                    .collect()
                    .await
                    .expect("second response body drains cleanly");

                assert_eq!(
                    accepted.load(std::sync::atomic::Ordering::SeqCst),
                    2,
                    "a response body dropped before EOF must never be reused"
                );
            })
            .await;
    }
}
