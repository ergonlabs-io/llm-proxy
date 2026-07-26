//! WP-13 v1 (thin slice): the router terminal filter. This is what
//! `proxy-core`'s HTTP connection manager wiring plugs in as the
//! [`crate::handler::StreamHandler`] at the *end* of the non-router
//! `http_filters` chain (mirroring Envoy's `envoy.filters.http.router`) --
//! matches a route (`crate::route`), picks a cluster + host through
//! `proxy_cluster::manager::ClusterManager`, dials/reuses an upstream
//! connection, and proxies the request over it with
//! [`crate::codec::send_upstream_http1`].
//!
//! ## v1 scope
//!
//! In scope: `Forward` routing to a `Cluster`/`ClusterHeader`/`Weighted`
//! target, HTTP/1.1 upstream only, connect-per-stream (no pooling/reuse --
//! see `proxy_cluster::pool`), `DirectResponse` for inline bodies, the
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
//! - HTTP/2 upstream (`UpstreamProtocol::Http2`).
//! - Connection reuse / real pooling (WP-15 follow-up;
//!   `ConnectPool` is connect-per-stream today).
//! - `RouteActionIR::Redirect` (returns 501 below).
//!
//! WP-24 chunk 3: response flags are recorded onto a per-request
//! [`StreamInfo`] (not just `tracing::debug!`'d) at every site below, and --
//! when the route's HCM has `access_logs` configured -- a rendered line is
//! written per logger once the response stream ends (`logging::LoggingBody`,
//! wrapped outermost in [`RouterHandler::handle`]). See `logging`'s module
//! doc for why that has to be at stream end, not at header-flush time.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use bytes::Bytes;
use http::{HeaderValue, StatusCode};
use http_body_util::{BodyExt, Full};
use proxy_cluster::manager::ClusterManager;
use proxy_cluster::{LoadBalancerContext, PoolError, RoutingPriority, UpstreamProtocol};
use proxy_config::ir::{
    AccessLogIR, DataSourceIR, ForwardTarget, RouteActionIR, RouteMatcher, RouteTable,
};
use proxy_observability::ResponseFlag;

use crate::codec::{send_upstream_http1, send_upstream_http2, Http1Options, UpstreamCodecError};
use crate::filter::{RequestHeaders, ResponseHeaders};
use crate::handler::{local_boxed, HttpRequestParts, HttpResponseParts, StreamBody, StreamHandler};
use crate::retry::{AttemptOutcome, RetryState};
use crate::route::{apply_prefix_rewrite, match_route, select_cluster, RouteMatch, RouteRequest};
use crate::stream_info::StreamInfo;
use guarded::GuardedBody;
use idle::IdleTimeoutBody;
use logging::{AccessLogContext, AccessLoggerRuntime, CountingRequestBody, LoggingBody};

mod guarded;
mod idle;
mod logging;

/// S3.4 (Envoy's `no_retry_body_too_large`): the largest request body this
/// router will hold in memory for retry replay. Matches
/// `filter_manager::DEFAULT_BUFFER_LIMIT` -- both exist for the same reason
/// (the decode chain is already fully buffered by the time a request reaches
/// the router terminal, so this doesn't add a *new* buffering cost, just caps
/// how much of what's already buffered upstream we're willing to hold a
/// second (replayable) copy of).
const RETRY_REQUEST_BUFFER_LIMIT: usize = 1 << 20;

/// The router terminal: matches a route, then forwards to the picked
/// cluster/host over a real upstream connection. See the module doc for v1
/// scope.
pub struct RouterHandler {
    route_table: Arc<RouteTable>,
    clusters: Arc<ClusterManager>,
    /// WP-24 chunk 3: this HCM's configured access loggers, already resolved
    /// to open sinks -- empty when the HCM has no `access_logs`, in which
    /// case [`RouterHandler::handle`] skips the logging wrap entirely.
    /// `Rc` (not `Arc`): shared cheaply across every request this
    /// (`!Send`, per-worker) handler serves, never across workers.
    access_loggers: Rc<Vec<AccessLoggerRuntime>>,
}

impl RouterHandler {
    pub fn new(route_table: Arc<RouteTable>, clusters: Arc<ClusterManager>) -> Self {
        Self {
            route_table,
            clusters,
            access_loggers: Rc::new(Vec::new()),
        }
    }

    /// Like [`Self::new`], but resolving `access_logs` into live sinks
    /// (opening/sharing files via a fresh [`logging::AccessLoggerRuntime`]
    /// registry scoped to this one build) -- what `proxy-core`'s
    /// `build_hcm_handler` calls, since every HCM in real config carries its
    /// own `access_logs`. Kept as a separate constructor (rather than adding
    /// a parameter to `new`) so every existing caller that has no sinks to
    /// build -- and so no `io::Error` to handle -- is unaffected.
    pub fn new_with_access_logs(
        route_table: Arc<RouteTable>,
        clusters: Arc<ClusterManager>,
        access_logs: &[AccessLogIR],
    ) -> std::io::Result<Self> {
        let registry = proxy_observability::sink::SinkRegistry::new();
        let access_loggers = AccessLoggerRuntime::build_all(access_logs, &registry)?;
        Ok(Self {
            route_table,
            clusters,
            access_loggers: Rc::new(access_loggers),
        })
    }
}

impl StreamHandler for RouterHandler {
    // Rust note: boxed/pinned future, same shape as `stub::FixedResponseHandler`
    // -- see `StreamHandler`'s own doc comment for why `async fn` in a trait
    // isn't an option here (object safety).
    fn handle<'a>(
        &'a self,
        req: HttpRequestParts,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HttpResponseParts> + 'a>> {
        Box::pin(async move { self.handle_and_log(req).await })
    }
}

impl RouterHandler {
    /// The `StreamHandler::handle` entry point: builds the per-request
    /// [`StreamInfo`] and access-log context, routes/forwards
    /// ([`Self::route_and_forward`]), then -- only if this HCM has
    /// `access_logs` configured -- wraps the response body in
    /// [`LoggingBody`] so a line is written once the stream actually ends.
    async fn handle_and_log(&self, req: HttpRequestParts) -> HttpResponseParts {
        let start_time = SystemTime::now();
        let start_instant = Instant::now();
        let downstream_remote_address = req.downstream.remote.to_string();

        // Rust note: snapshot the *pre-router* request headers for logging.
        // This already reflects any S9 mutations the filter chain made
        // upstream of the router (x-request-id, XFF, ...), but deliberately
        // not this route's own `request_headers_to_add` (provider
        // credentials injected later, in `apply_request_transforms`) -- an
        // access log must never become a place a dialect-injected
        // `Authorization`/`x-api-key` header leaks to.
        let mut request_headers = req.head.headers.clone();
        // `%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%` (the default access-log
        // format's own path field) falls back to a `:PATH` pseudo-header
        // `header_lookup` can never resolve (see its doc in
        // `proxy_observability::access_log`) -- populating the *primary*
        // here, the same normal header name real Envoy sets on a
        // `prefix_rewrite`, is what makes that default format usable at all
        // for the path, without touching the (frozen) formatter itself.
        let original_path = req.head.uri.path().to_string();
        if !request_headers.contains_key("x-envoy-original-path") {
            if let Ok(v) = HeaderValue::from_str(&original_path) {
                request_headers.insert("x-envoy-original-path", v);
            }
        }

        let stream_info = Rc::new(RefCell::new(StreamInfo::default()));
        let resp = self.route_and_forward(req, stream_info.clone()).await;

        if self.access_loggers.is_empty() {
            return resp;
        }

        let ctx = AccessLogContext {
            loggers: self.access_loggers.clone(),
            stream_info,
            start_time,
            start_instant,
            request_headers,
            response_headers: resp.head.headers.clone(),
            response_code: resp.head.status.as_u16(),
            downstream_remote_address,
        };
        HttpResponseParts {
            head: resp.head,
            body: local_boxed(LoggingBody::new(resp.body, ctx)),
        }
    }

    async fn route_and_forward(
        &self,
        req: HttpRequestParts,
        stream_info: Rc<RefCell<StreamInfo>>,
    ) -> HttpResponseParts {
        // Rust note: `req.head.uri.authority()` borrows from `req.head`, so
        // this has to be resolved before `req` is destructured/moved below;
        // the `Host` header fallback borrows from the same `req.head`.
        let host_header = req
            .head
            .headers
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok());
        let authority = req
            .head
            .uri
            .authority()
            .map(|a| a.as_str())
            .or(host_header)
            .unwrap_or("");
        let path = req
            .head
            .uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");

        let route_req = RouteRequest {
            authority,
            path,
            headers: &req.head.headers,
        };

        // Rust note: `match_route` borrows from `self.route_table` (its `'t`
        // lifetime) and from `route_req` (which itself borrows `req.head`),
        // so the match has to be fully handled -- and `req`'s body drained or
        // moved on -- before this function returns.
        match match_route(&self.route_table, &route_req) {
            RouteMatch::NoVirtualHost | RouteMatch::NoRoute { .. } => {
                tracing::debug!(response_flag = "NR", authority, path, "no route matched");
                stream_info
                    .borrow_mut()
                    .set_response_flag(ResponseFlag::NoRouteFound);
                drain_request_body(req).await;
                local_reply(StatusCode::NOT_FOUND, "no route matched")
            }
            RouteMatch::Found { route, .. } => match &route.action {
                RouteActionIR::Forward(fwd) => {
                    self.apply_forward(
                        fwd,
                        &route.matcher,
                        &route.request_headers_to_add,
                        req,
                        stream_info,
                    )
                    .await
                }
                RouteActionIR::DirectResponse { status, body } => {
                    drain_request_body(req).await;
                    direct_response(*status, body.as_ref())
                }
                RouteActionIR::Redirect(_) => {
                    tracing::debug!(
                        "TODO(WP-13 follow-up: redirects) -- redirect action not yet implemented"
                    );
                    drain_request_body(req).await;
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
        req: HttpRequestParts,
        stream_info: Rc<RefCell<StreamInfo>>,
    ) -> HttpResponseParts {
        let draw = match &fwd.target {
            ForwardTarget::Weighted(w) if w.total_weight > 0 => {
                rand::random::<u64>() % w.total_weight
            }
            _ => 0,
        };

        let Some(cluster_name) = select_cluster(&fwd.target, &req.head.headers, draw) else {
            tracing::debug!(
                response_flag = "NC",
                "forward target resolved to no cluster"
            );
            stream_info
                .borrow_mut()
                .set_response_flag(ResponseFlag::NoClusterFound);
            drain_request_body(req).await;
            return local_reply(StatusCode::SERVICE_UNAVAILABLE, "no cluster");
        };
        // Rust note: `select_cluster` borrows `cluster_name` from
        // `req.head.headers` (the `ClusterHeader` case) or from `fwd.target`
        // (a `'static`-ish `String` living in the route table) -- either way
        // it's tied to `req`/`self`'s lifetime, so it has to be copied out
        // (`to_string`) before `req` is consumed below.
        let cluster_name = cluster_name.to_string();

        let Some(entry) = self.clusters.cluster(&cluster_name) else {
            tracing::debug!(response_flag = "NC", cluster = %cluster_name, "unknown cluster");
            stream_info
                .borrow_mut()
                .set_response_flag(ResponseFlag::NoClusterFound);
            drain_request_body(req).await;
            return local_reply(StatusCode::SERVICE_UNAVAILABLE, "unknown cluster");
        };

        // Rust note: `downstream` is `Copy`, so this reads it out before
        // `req.head`/`req.body` are moved below (a partial move of `req`) --
        // provenance flows from the accepted downstream connection onto every
        // upstream request the router builds, retried or not.
        let downstream = req.downstream;
        let mut head = req.head;
        apply_request_transforms(fwd, matcher, request_headers_to_add, &mut head);

        // WP-14 (S3): a route with a retry policy has to be able to replay
        // its request body on every attempt, so it's collected into `Bytes`
        // once, up front, instead of streamed straight through. A route with
        // no policy keeps the original zero-copy streaming path -- exactly
        // one attempt is ever made, so there's nothing to replay and no
        // buffering cost to pay. Rust note: exactly one of
        // `streaming_body`/`buffered_body` is ever populated below; a plain
        // two-variant enum would say that more strongly, but would still need
        // an unreachable third arm for "neither" -- these two `Option`s do
        // the same job with less ceremony.
        let mut retry_state = fwd.retry_policy.as_ref().map(RetryState::new);
        let mut streaming_body: Option<StreamBody> = None;
        let buffered_body: Option<Bytes> = match &mut retry_state {
            Some(state) => match req.body.collect().await {
                Ok(collected) => {
                    let bytes = collected.to_bytes();
                    if bytes.len() > RETRY_REQUEST_BUFFER_LIMIT {
                        // S3.4 (Envoy's `no_retry_body_too_large`): too big to
                        // safely hold a second copy of for replay. The
                        // request still proceeds -- it just can't be retried.
                        state.mark_body_not_retriable();
                    }
                    // WP-24: the retry/replay path already has the whole
                    // body in hand, so `%BYTES_RECEIVED%` is exact and free
                    // -- no need for the streaming path's frame-by-frame
                    // counter below.
                    stream_info.borrow_mut().bytes_received = bytes.len() as u64;
                    Some(bytes)
                }
                Err(_) => {
                    return local_reply(StatusCode::BAD_REQUEST, "failed to read request body");
                }
            },
            None => {
                // WP-24: wrapped so `%BYTES_RECEIVED%` reflects what's
                // actually forwarded upstream, one frame at a time, instead
                // of staying 0 for every non-retry (i.e. most) request.
                streaming_body = Some(local_boxed(CountingRequestBody::new(
                    req.body,
                    stream_info.clone(),
                )));
                None
            }
        };

        // S4: `fwd.timeout`, when set, is an *overall* budget across every
        // attempt (Envoy's route `timeout` is not a per-try timeout -- the IR
        // has no per-try timeout field, see `RetryPolicyIR::per_try_timeout`'s
        // doc), so it wraps the whole attempt loop below rather than a single
        // `send`. With no retry policy the loop runs exactly once, so this is
        // unobservable from a no-retry route's point of view.
        let attempt_loop = async {
            loop {
                // S5: acquire a `max_requests` permit for this attempt before
                // doing any more work for it. Requests are priority `Default`
                // for now -- per-priority route selection is a later WP.
                // Rust note: scoped to one loop iteration, so `continue`
                // (a retry) drops it and the next attempt acquires fresh --
                // exactly what "an attempt is free to land on a different
                // host" implies for its circuit-breaker accounting too.
                let cb = entry.circuit_breaker(RoutingPriority::Default);
                let Some(rq_guard) = cb.try_acquire_request() else {
                    tracing::debug!(response_flag = "UO", cluster = %cluster_name, "circuit breaker: max_requests exceeded");
                    stream_info
                        .borrow_mut()
                        .set_response_flag(ResponseFlag::UpstreamOverflow);
                    drain_leftover_body(&mut streaming_body).await;
                    let mut resp =
                        local_reply(StatusCode::SERVICE_UNAVAILABLE, "upstream overloaded");
                    resp.head
                        .headers
                        .insert("x-envoy-overloaded", HeaderValue::from_static("true"));
                    return resp;
                };

                let ctx = LoadBalancerContext::default();
                let Some(host) = entry.pick_host(&ctx) else {
                    tracing::debug!(response_flag = "UH", cluster = %cluster_name, "no healthy upstream host");
                    stream_info
                        .borrow_mut()
                        .set_response_flag(ResponseFlag::NoHealthyUpstream);
                    drain_leftover_body(&mut streaming_body).await;
                    return local_reply(StatusCode::SERVICE_UNAVAILABLE, "no healthy upstream");
                };

                let proto = entry.upstream_protocol();
                // WP-24: both known right here, at the dial site -- recorded
                // onto `StreamInfo` for `%UPSTREAM_HOST%`/`%UPSTREAM_CLUSTER%`/
                // `%PROTOCOL%` before the connect is even attempted, so a
                // failed attempt still logs which host/cluster/protocol it
                // was aimed at (matching Envoy's own access-log behavior on
                // an upstream failure). A later retry attempt overwrites
                // these with its own host, which is what makes the *last*
                // attempt's target the one that ends up logged.
                {
                    let mut info = stream_info.borrow_mut();
                    info.upstream_cluster = Some(cluster_name.clone());
                    info.upstream_host = Some(host.address.to_string());
                    info.protocol = Some(
                        match proto {
                            UpstreamProtocol::Http1 => "HTTP/1.1",
                            UpstreamProtocol::Http2 => "HTTP/2",
                        }
                        .to_string(),
                    );
                }
                let pool = entry.http_pool(&host, proto);
                let upstream = match pool.new_stream().await {
                    Ok(upstream) => upstream,
                    Err(err) => {
                        let outcome = AttemptOutcome::from_pool_error(&err);
                        if let Some(state) = &mut retry_state {
                            if state.should_retry(&outcome) {
                                sleep_backoff_and_record(state).await;
                                continue;
                            }
                        }
                        drain_leftover_body(&mut streaming_body).await;
                        return match err {
                            PoolError::Overflow => {
                                tracing::debug!(response_flag = "UO", cluster = %cluster_name, "pool overflow");
                                stream_info
                                    .borrow_mut()
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
                                tracing::debug!(response_flag = "UF", cluster = %cluster_name, "upstream connect failure");
                                stream_info
                                    .borrow_mut()
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
                            // half actually broke.
                            PoolError::TlsHandshake(_) => {
                                tracing::debug!(response_flag = "UF", cluster = %cluster_name, "upstream TLS handshake failure");
                                stream_info
                                    .borrow_mut()
                                    .set_response_flag(ResponseFlag::UpstreamConnectionFailure);
                                local_reply(
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    "upstream connect failure",
                                )
                            }
                            PoolError::ResetBeforeHeaders => {
                                tracing::debug!(response_flag = "UR", cluster = %cluster_name, "upstream reset before headers");
                                stream_info
                                    .borrow_mut()
                                    .set_response_flag(ResponseFlag::UpstreamRemoteReset);
                                local_reply(StatusCode::SERVICE_UNAVAILABLE, "upstream reset")
                            }
                        };
                    }
                };

                // Rust note: a fresh `RequestHeaders` for this attempt --
                // `head` itself stays owned by the outer scope for the *next*
                // attempt, so this clones the (small) method/uri/header-map
                // trio rather than moving `head` away after one use.
                let attempt_head = RequestHeaders {
                    method: head.method.clone(),
                    uri: head.uri.clone(),
                    headers: head.headers.clone(),
                };
                // Rust note: the streaming body can only be taken once (it's
                // not `Clone` -- it's a boxed, single-consumption stream), so
                // `.take()` empties it after the first (only, since no retry
                // policy implies no second iteration) use; the buffered
                // variant is plain `Bytes`, cheap (refcounted) to `.clone()`
                // fresh for every attempt.
                let attempt_body: StreamBody = match streaming_body.take() {
                    Some(body) => body,
                    None => body_from_bytes(
                        buffered_body
                            .clone()
                            .expect("retry policy implies buffered_body is populated"),
                    ),
                };

                let upstream_req = HttpRequestParts {
                    head: attempt_head,
                    body: attempt_body,
                    downstream,
                };

                // Dispatch on the cluster's configured upstream protocol.
                // Both codecs yield the same
                // `Result<HttpResponseParts, UpstreamCodecError>`; box the
                // future so the two arms share one type. h2 here is
                // prior-knowledge cleartext (h2c) over the pool's raw TCP
                // stream -- no per-request `Connection: close`, so it takes
                // no `Http1Options`.
                let send: std::pin::Pin<
                    Box<
                        dyn std::future::Future<
                            Output = Result<HttpResponseParts, UpstreamCodecError>,
                        >,
                    >,
                > = match proto {
                    UpstreamProtocol::Http1 => Box::pin(send_upstream_http1(
                        upstream.io,
                        upstream_req,
                        Http1Options { keep_alive: false },
                    )),
                    UpstreamProtocol::Http2 => {
                        Box::pin(send_upstream_http2(upstream.io, upstream_req))
                    }
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
                            let outcome = AttemptOutcome::PerTryTimeout;
                            if let Some(state) = &mut retry_state {
                                if state.should_retry(&outcome) {
                                    sleep_backoff_and_record(state).await;
                                    continue;
                                }
                            }
                            tracing::debug!(
                                response_flag = "UT",
                                cluster = %cluster_name,
                                timeout_ms = d.as_millis(),
                                "upstream per-try timeout waiting for response headers"
                            );
                            stream_info
                                .borrow_mut()
                                .set_response_flag(ResponseFlag::UpstreamRequestTimeout);
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
                        let outcome = AttemptOutcome::from_codec_error(&err);
                        if let Some(state) = &mut retry_state {
                            if state.should_retry(&outcome) {
                                sleep_backoff_and_record(state).await;
                                continue;
                            }
                        }
                        tracing::debug!(response_flag = "UC", cluster = %cluster_name, "upstream codec error");
                        stream_info
                            .borrow_mut()
                            .set_response_flag(ResponseFlag::UpstreamConnectionTermination);
                        return local_reply(StatusCode::BAD_GATEWAY, "upstream connection failure");
                    }
                }
            }
        };

        match fwd.timeout {
            Some(d) => {
                // Rust note: `tokio::time::timeout` races the whole attempt
                // loop against a timer; on `Err(Elapsed)` the loop future
                // (and whatever upstream connection/attempt it's mid-flight
                // on) is dropped, which closes/resets that connection --
                // exactly Envoy's `UT` behavior of abandoning a request that
                // didn't get response headers, across every attempt, in
                // time.
                match tokio::time::timeout(d, attempt_loop).await {
                    Ok(resp) => resp,
                    Err(_elapsed) => {
                        tracing::debug!(
                            response_flag = "UT",
                            cluster = %cluster_name,
                            timeout_ms = d.as_millis(),
                            "upstream request timed out waiting for response headers"
                        );
                        stream_info
                            .borrow_mut()
                            .set_response_flag(ResponseFlag::UpstreamRequestTimeout);
                        local_reply(StatusCode::GATEWAY_TIMEOUT, "upstream request timeout")
                    }
                }
            }
            None => attempt_loop.await,
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

/// Drain (and discard) a request body that was never handed to an upstream
/// attempt -- e.g. a circuit-breaker/pick-host/connect failure before the
/// streaming body was ever taken. Only the (at most once) streaming path
/// ever has anything left to drain here: the buffered/replay path collects
/// the whole body up front, so by the time an attempt can fail there's
/// nothing left on the wire to read. Mirrors `drain_request_body`'s
/// rationale: a local reply that never reads the body must still consume it
/// so the downstream connection isn't left with unread bytes.
async fn drain_leftover_body(streaming_body: &mut Option<StreamBody>) {
    if let Some(body) = streaming_body.take() {
        let _ = body.collect().await;
    }
}

/// Build a fresh, single-use [`StreamBody`] from already-buffered bytes --
/// used to replay a retried request's body on each attempt.
fn body_from_bytes(bytes: Bytes) -> StreamBody {
    local_boxed(
        Full::new(bytes).map_err(|infallible: std::convert::Infallible| match infallible {}),
    )
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

/// Drain (and discard) the request body -- mirrors
/// `stub::FixedResponseHandler`'s handling: a local reply that never reads
/// the body must still consume it so the downstream connection isn't left
/// with unread bytes.
async fn drain_request_body(req: HttpRequestParts) {
    let _ = req.body.collect().await;
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
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::time::Duration;

    use http::{HeaderMap, Method, StatusCode, Uri};
    use proxy_cluster::manager::ClusterManager;
    use proxy_cluster::resolver::FakeResolver;
    use proxy_config::ir::{
        CircuitBreakerThresholds, CircuitBreakers, ClusterConfig, ClusterName, DiscoveryType,
        EndpointIR, ForwardAction, ForwardTarget, LbPolicy, PathMatch, RouteEntry, RouteMatcher,
        RouteTable, VirtualHostIR,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio::task::LocalSet;

    use super::*;
    use crate::filter::RequestHeaders;
    use crate::handler::{DownstreamInfo, StreamHandler};

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

    /// Build a one-cluster, one-route `RouterHandler` forwarding to `addr`
    /// under cluster name `"up"`.
    async fn build_router(
        addr: SocketAddr,
        matcher: RouteMatcher,
        fwd: ForwardAction,
    ) -> RouterHandler {
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
    ) -> RouterHandler {
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
                transport_socket: None,
                per_connection_buffer_limit_bytes: 1 << 20,
                circuit_breakers,
                upstream_protocol: proxy_config::ir::UpstreamProtocol::Http1,
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
                })],
            }],
        )
        .unwrap();

        RouterHandler::new(Arc::new(route_table), Arc::new(manager))
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
}
