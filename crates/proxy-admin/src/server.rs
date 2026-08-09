//! The admin HTTP server: binds a socket (control runtime, ADR-0003) and
//! answers the read-only endpoints over real hyper connections.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use proxy_core::WorkerConfigHandle;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::dump::{ClusterDump, ConfigDump};

/// The endpoints this increment serves, used both to route requests and to
/// list "available endpoints" in a 404 body.
const AVAILABLE_ENDPOINTS: &[&str] = &["/ready", "/config_dump", "/clusters", "/server_info"];

#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("admin server failed to bind {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
}

/// A running admin server. Dropping this does not stop the server -- see
/// [`AdminServer::abort`] -- so callers that care about shutdown (none do
/// yet in this read-only increment) must call it explicitly.
pub struct AdminServer {
    local_addr: SocketAddr,
    accept_task: JoinHandle<()>,
}

impl AdminServer {
    /// The address actually bound -- callers pass port 0 in tests and read
    /// the OS-assigned port back from here.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Stops accepting new connections. In-flight requests on already
    /// accepted connections may still complete (each runs on its own
    /// spawned task, independent of this handle).
    pub fn abort(&self) {
        self.accept_task.abort();
    }
}

/// Binds `addr` and starts answering admin requests on the control runtime.
///
/// `config` is read (never owned) per request via `load()` -- an `Arc`
/// clone of whatever the control side last published, per ADR-0005's
/// "control computes, workers read" split applied to this reader too.
/// `started_at` backs `/server_info`'s uptime.
///
/// Rust note: `TcpListener::accept` runs in a loop inside a `tokio::spawn`led
/// task; each accepted connection gets its own further-spawned task running
/// one `hyper::server::conn::http1` connection, the standard hyper-on-tokio
/// shape. Nothing here needs `!Send`/`Rc` -- this is ordinary control-plane
/// code, never the worker-local data plane (ADR-0003).
pub async fn serve(
    addr: SocketAddr,
    config: Arc<WorkerConfigHandle>,
    started_at: Instant,
) -> Result<AdminServer, AdminError> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|source| AdminError::Bind { addr, source })?;
    let local_addr = listener
        .local_addr()
        .map_err(|source| AdminError::Bind { addr, source })?;

    let accept_task = tokio::spawn(async move {
        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(err) => {
                    tracing::warn!(error = %err, "admin server: accept failed, continuing");
                    continue;
                }
            };
            let io = TokioIo::new(stream);
            let config = config.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req| {
                    let config = config.clone();
                    async move { Ok::<_, std::convert::Infallible>(handle(req, &config, started_at)) }
                });
                if let Err(err) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await
                {
                    tracing::debug!(error = %err, "admin server: connection error");
                }
            });
        }
    });

    Ok(AdminServer {
        local_addr,
        accept_task,
    })
}

fn handle(
    req: Request<Incoming>,
    config: &WorkerConfigHandle,
    started_at: Instant,
) -> Response<Full<Bytes>> {
    match req.uri().path() {
        "/ready" => text(StatusCode::OK, "LIVE"),
        "/config_dump" => {
            let snapshot = config.load();
            json(StatusCode::OK, &ConfigDump::from_snapshot(&snapshot))
        }
        "/clusters" => {
            let snapshot = config.load();
            let mut clusters: Vec<ClusterDump> = snapshot
                .clusters
                .values()
                .map(|c| ClusterDump::from_ir(c))
                .collect();
            clusters.sort_by(|a, b| a.name.cmp(&b.name));
            json(StatusCode::OK, &clusters)
        }
        "/server_info" => {
            let uptime_seconds = started_at.elapsed().as_secs();
            json(
                StatusCode::OK,
                &ServerInfo {
                    version: env!("CARGO_PKG_VERSION"),
                    uptime_seconds,
                },
            )
        }
        "/stats" => text(
            StatusCode::NOT_FOUND,
            "not implemented yet (WP-23: stats registry); this proxy does not fake an empty /stats",
        ),
        other => text(
            StatusCode::NOT_FOUND,
            &format!(
                "unknown admin endpoint '{other}'; available endpoints: {}",
                AVAILABLE_ENDPOINTS.join(", ")
            ),
        ),
    }
}

#[derive(serde::Serialize)]
struct ServerInfo {
    version: &'static str,
    uptime_seconds: u64,
}

fn text(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
        .expect("static response is always valid")
}

fn json<T: serde::Serialize>(status: StatusCode, value: &T) -> Response<Full<Bytes>> {
    match serde_json::to_vec(value) {
        Ok(bytes) => Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(bytes)))
            .expect("static response is always valid"),
        Err(err) => {
            tracing::error!(error = %err, "admin server: failed to serialize response");
            text(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to serialize response",
            )
        }
    }
}

#[cfg(test)]
mod tests;
