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
//!   `Http1ConnectPool` is connect-per-stream today).
//! - `RouteActionIR::Redirect` (returns 501 below).
//!
//! There is no access-log sink yet (WP-24): response flags are only ever
//! `tracing::debug!`/`tracing::warn!`'d here, never recorded as stats.

use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderValue, StatusCode};
use http_body_util::{BodyExt, Full};
use proxy_cluster::manager::ClusterManager;
use proxy_cluster::{LoadBalancerContext, PoolError, RoutingPriority, UpstreamProtocol};
use proxy_config::ir::{DataSourceIR, ForwardTarget, RouteActionIR, RouteMatcher, RouteTable};

use crate::codec::{send_upstream_http1, Http1Options, UpstreamCodecError};
use crate::filter::ResponseHeaders;
use crate::handler::{local_boxed, HttpRequestParts, HttpResponseParts, StreamBody, StreamHandler};
use crate::route::{apply_prefix_rewrite, match_route, select_cluster, RouteMatch, RouteRequest};
use guarded::GuardedBody;
use idle::IdleTimeoutBody;

mod guarded;
mod idle;

/// The router terminal: matches a route, then forwards to the picked
/// cluster/host over a real upstream connection. See the module doc for v1
/// scope.
pub struct RouterHandler {
    route_table: Arc<RouteTable>,
    clusters: Arc<ClusterManager>,
}

impl RouterHandler {
    pub fn new(route_table: Arc<RouteTable>, clusters: Arc<ClusterManager>) -> Self {
        Self {
            route_table,
            clusters,
        }
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
        Box::pin(async move { self.route_and_forward(req).await })
    }
}

impl RouterHandler {
    async fn route_and_forward(&self, req: HttpRequestParts) -> HttpResponseParts {
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
                drain_request_body(req).await;
                local_reply(StatusCode::NOT_FOUND, "no route matched")
            }
            RouteMatch::Found { route, .. } => match &route.action {
                RouteActionIR::Forward(fwd) => self.apply_forward(fwd, &route.matcher, req).await,
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
        req: HttpRequestParts,
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
            drain_request_body(req).await;
            return local_reply(StatusCode::SERVICE_UNAVAILABLE, "unknown cluster");
        };

        // S5: acquire a `max_requests` permit for this cluster before doing
        // any more work for it. Requests are priority `Default` for now --
        // per-priority route selection (routing a request to the `HIGH`
        // bucket) is a later WP; every request lands in the same bucket
        // until then.
        let cb = entry.circuit_breaker(RoutingPriority::Default);
        let Some(rq_guard) = cb.try_acquire_request() else {
            tracing::debug!(response_flag = "UO", cluster = %cluster_name, "circuit breaker: max_requests exceeded");
            drain_request_body(req).await;
            let mut resp = local_reply(StatusCode::SERVICE_UNAVAILABLE, "upstream overloaded");
            resp.head
                .headers
                .insert("x-envoy-overloaded", HeaderValue::from_static("true"));
            return resp;
        };

        let ctx = LoadBalancerContext::default();
        let Some(host) = entry.pick_host(&ctx) else {
            tracing::debug!(response_flag = "UH", cluster = %cluster_name, "no healthy upstream host");
            drain_request_body(req).await;
            return local_reply(StatusCode::SERVICE_UNAVAILABLE, "no healthy upstream");
        };

        let pool = entry.http_pool(&host, UpstreamProtocol::Http1);
        let upstream = match pool.new_stream().await {
            Ok(upstream) => upstream,
            Err(PoolError::Overflow) => {
                tracing::debug!(response_flag = "UO", cluster = %cluster_name, "pool overflow");
                drain_request_body(req).await;
                let mut resp = local_reply(StatusCode::SERVICE_UNAVAILABLE, "upstream overloaded");
                resp.head
                    .headers
                    .insert("x-envoy-overloaded", HeaderValue::from_static("true"));
                return resp;
            }
            Err(PoolError::ConnectFailure(_)) | Err(PoolError::ConnectTimeout) => {
                tracing::debug!(response_flag = "UF", cluster = %cluster_name, "upstream connect failure");
                drain_request_body(req).await;
                return local_reply(StatusCode::SERVICE_UNAVAILABLE, "upstream connect failure");
            }
            Err(PoolError::ResetBeforeHeaders) => {
                tracing::debug!(response_flag = "UR", cluster = %cluster_name, "upstream reset before headers");
                drain_request_body(req).await;
                return local_reply(StatusCode::SERVICE_UNAVAILABLE, "upstream reset");
            }
        };

        // Rust note: `downstream` is `Copy`, so this reads it out before
        // `req.head`/`req.body` are moved below (a partial move of `req`) --
        // provenance flows from the accepted downstream connection onto the
        // upstream request the router builds.
        let downstream = req.downstream;
        let mut upstream_req = HttpRequestParts {
            head: req.head,
            body: req.body,
            downstream,
        };
        apply_request_transforms(fwd, matcher, &mut upstream_req.head);

        let send = send_upstream_http1(
            upstream.io,
            upstream_req,
            Http1Options { keep_alive: false },
        );

        let result = match fwd.timeout {
            Some(d) => {
                // Rust note: `tokio::time::timeout` races `send` against a
                // timer; on `Err(Elapsed)` the `send` future (and the
                // `upstream.io` it owns) is dropped, which closes/resets the
                // upstream connection -- exactly Envoy's `UT` behavior of
                // abandoning a request that didn't get response headers in
                // time. Once headers arrive (`Ok(Ok(_))`), the timeout is
                // fully out of the picture: the *body* stream returned below
                // has no further deadline (S4 -- this is what makes
                // LLM-streaming routes safe to bound this way).
                match tokio::time::timeout(d, send).await {
                    Ok(inner) => inner,
                    Err(_elapsed) => {
                        tracing::debug!(
                            response_flag = "UT",
                            cluster = %cluster_name,
                            timeout_ms = d.as_millis(),
                            "upstream request timed out waiting for response headers"
                        );
                        return local_reply(
                            StatusCode::GATEWAY_TIMEOUT,
                            "upstream request timeout",
                        );
                    }
                }
            }
            None => send.await,
        };

        match result {
            Ok(mut resp) => {
                // Rust note: the route `timeout` above is fully spent once
                // headers arrive -- this is the independent, response-body-
                // only deadline that picks up from there. Wrapping only on
                // the success path (not the error/local-reply arms) is
                // deliberate: `idle_timeout` bounds inter-frame gaps in a
                // response we actually got, not the absence of one.
                if let Some(idle) = fwd.idle_timeout {
                    resp.body = local_boxed(IdleTimeoutBody::new(resp.body, idle));
                }
                // S5: wrap outermost (after any idle_timeout wrap) so the
                // `max_requests` permit is held until the very last response
                // frame is produced or the body is dropped, whichever comes
                // first -- not just until headers arrive.
                resp.body = local_boxed(GuardedBody::new(resp.body, rq_guard));
                resp
            }
            Err(UpstreamCodecError::Handshake(_))
            | Err(UpstreamCodecError::Connection(_))
            | Err(UpstreamCodecError::Send(_))
            // `MissingAuthority` is h2-only (unreachable via `send_upstream_http1`,
            // which this router chunk exclusively drives) but must be handled here
            // since the match is over the shared `UpstreamCodecError` enum.
            | Err(UpstreamCodecError::MissingAuthority) => {
                tracing::debug!(response_flag = "UC", cluster = %cluster_name, "upstream codec error");
                local_reply(StatusCode::BAD_GATEWAY, "upstream connection failure")
            }
        }
    }
}

/// Apply the S13/S4 upstream request transforms to the outgoing request
/// head, in place, before it's handed to `send_upstream_http1`:
/// `prefix_rewrite` (rewrites `head.uri`), `host_rewrite_literal` (rewrites
/// the `Host` header, which is what carries `:authority` over h1), and the
/// `x-envoy-expected-rq-timeout-ms` header Envoy sets from the route's S4
/// timeout so the upstream knows its deadline.
fn apply_request_transforms(
    fwd: &proxy_config::ir::ForwardAction,
    matcher: &RouteMatcher,
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
        let manager = ClusterManager::new(Arc::new(FakeResolver::new()));
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
