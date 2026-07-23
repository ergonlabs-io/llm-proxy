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
//! see `proxy_cluster::pool`), and `DirectResponse` for inline bodies.
//!
//! Deferred (known feature gaps, not silent drops -- ground rule #1):
//! - S9 request-header transforms: XFF, `x-request-id`, `:authority`
//!   rewrite. `crate::headers` already implements the functions; this
//!   router doesn't call them yet.
//! - `prefix_rewrite`/`host_rewrite_literal` (present in the IR's
//!   `ForwardAction`, not yet applied here -- see the `tracing::debug!` in
//!   `apply_forward` below).
//! - S4 timeouts (`ForwardAction::timeout`/`idle_timeout`).
//! - Circuit-breaker checks (`ClusterEntry::circuit_breaker`) before
//!   dialing.
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
use proxy_cluster::{LoadBalancerContext, PoolError, UpstreamProtocol};
use proxy_config::ir::{DataSourceIR, ForwardTarget, RouteActionIR, RouteTable};

use crate::codec::{send_upstream_http1, Http1Options, UpstreamCodecError};
use crate::filter::ResponseHeaders;
use crate::handler::{local_boxed, HttpRequestParts, HttpResponseParts, StreamBody, StreamHandler};
use crate::route::{match_route, select_cluster, RouteMatch, RouteRequest};

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
            RouteMatch::Found { route, .. } => {
                match &route.action {
                    RouteActionIR::Forward(fwd) => self.apply_forward(fwd, req).await,
                    RouteActionIR::DirectResponse { status, body } => {
                        drain_request_body(req).await;
                        direct_response(*status, body.as_ref())
                    }
                    RouteActionIR::Redirect(_) => {
                        tracing::debug!("TODO(WP-13 follow-up: redirects) -- redirect action not yet implemented");
                        drain_request_body(req).await;
                        local_reply(
                            StatusCode::NOT_IMPLEMENTED,
                            "redirect actions are not yet implemented",
                        )
                    }
                }
            }
        }
    }

    async fn apply_forward(
        &self,
        fwd: &proxy_config::ir::ForwardAction,
        req: HttpRequestParts,
    ) -> HttpResponseParts {
        if fwd.prefix_rewrite.is_some() || fwd.host_rewrite_literal.is_some() {
            // Known feature gap (see module doc): the IR carries the rewrite,
            // it just isn't applied to the outgoing request yet.
            tracing::debug!(
                "TODO(WP-13 follow-up): route configures prefix_rewrite/host_rewrite_literal, not yet applied at runtime"
            );
        }

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

        let upstream_req = HttpRequestParts {
            head: req.head,
            body: req.body,
        };
        match send_upstream_http1(
            upstream.io,
            upstream_req,
            Http1Options { keep_alive: false },
        )
        .await
        {
            Ok(resp) => resp,
            Err(UpstreamCodecError::Handshake(_))
            | Err(UpstreamCodecError::Connection(_))
            | Err(UpstreamCodecError::Send(_)) => {
                tracing::debug!(response_flag = "UC", cluster = %cluster_name, "upstream codec error");
                local_reply(StatusCode::BAD_GATEWAY, "upstream connection failure")
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
