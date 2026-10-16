//! `tcp_proxy` network filter runtime, the first terminal L4 filter. It resolves an upstream endpoint for a matched
//! connection, connects, and pumps bytes both ways until either side closes, the connection idles out, or a drain
//! shutdown fires.
//!
//! Endpoint selection is minimal: the first `priority == 0` endpoint. The cluster-manager machinery in `proxy-cluster`
//! is not used here yet.

use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use proxy_config::ir::ClusterName;
use proxy_config::ConfigSnapshot;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;

use crate::drain::ConnectionGuard;

/// Owned parameters for one tcp_proxy'd connection, extracted from the
/// matched chain's `TcpProxyConfig` before the downstream stream is handed
/// off to [`proxy_connection`] -- cheap owned data, no lifetime tangles with
/// the snapshot/stream.
pub struct TcpProxyParams {
    pub cluster: ClusterName,
    pub idle_timeout: Option<Duration>,
    pub max_connect_attempts: u32,
    pub buffer_limit: u32,
}

/// Resolves an upstream target address for `cluster` from `snapshot`: the first `priority == 0` endpoint in
/// declaration order. `None` (cluster missing, or no priority-0 endpoint) fails the connection.
///
/// TODO: real load balancing per `LbPolicy`. This always picks the same endpoint.
fn resolve_target(snapshot: &ConfigSnapshot, cluster: &str) -> Option<(String, u16, Duration)> {
    let cluster_ir = snapshot.clusters.get(cluster)?;
    let endpoint = cluster_ir.endpoints.iter().find(|e| e.priority == 0)?;
    Some((
        endpoint.host.clone(),
        endpoint.port,
        cluster_ir.connect_timeout,
    ))
}

/// Connects to `(host, port)` up to `max_attempts` times, each bounded by `connect_timeout`. There is no backoff
/// between attempts, since Envoy's `backoff_options` is not in the IR yet.
///
/// Rust note: `(host, port)` resolves both IP literals and DNS names through the system resolver. DNS endpoints
/// connect here, but full StrictDns re-resolution belongs to `proxy-cluster`.
async fn connect_upstream(
    host: &str,
    port: u16,
    connect_timeout: Duration,
    max_attempts: u32,
) -> Option<TcpStream> {
    for attempt in 1..=max_attempts.max(1) {
        match tokio::time::timeout(connect_timeout, TcpStream::connect((host, port))).await {
            Ok(Ok(stream)) => {
                if let Err(err) = stream.set_nodelay(true) {
                    tracing::debug!(error = %err, "failed to set TCP_NODELAY on upstream socket");
                }
                return Some(stream);
            }
            Ok(Err(err)) => {
                tracing::debug!(%host, port, attempt, error = %err, "tcp_proxy: upstream connect failed");
            }
            Err(_) => {
                tracing::debug!(%host, port, attempt, "tcp_proxy: upstream connect timed out");
            }
        }
    }
    None
}

/// Copies one direction: reads from `r`, writes to `w`, until `r` hits EOF or an error, then sends FIN on `w`.
/// Every read bumps `last_activity`, so the idle timer in [`pump`] sees traffic in either direction.
///
/// Rust note: each direction is its own future, not two arms of one `select!`. Two concurrently polled halves keep the
/// pump deadlock-free under backpressure: if one half parks on a slow `write_all`, the other still drains its read side,
/// which often unblocks the stalled write. A single `select!` that reads and writes in one arm would park the whole task
/// on one write and starve the other direction.
async fn half_copy<R, W>(mut r: R, mut w: W, last_activity: Rc<Cell<Instant>>, buffer_limit: u32)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; buffer_limit.max(1) as usize];
    loop {
        match r.read(&mut buf).await {
            // EOF or read error: half-close by sending FIN on the write side. The other direction keeps flowing.
            Ok(0) | Err(_) => {
                let _ = w.shutdown().await;
                return;
            }
            Ok(n) => {
                last_activity.set(Instant::now());
                // Peer's write side gone: nothing more we can deliver this
                // way; the opposite half will wind down on its own read error.
                if w.write_all(&buf[..n]).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// Bidirectional pump with half-close (FIN propagation) and an optional idle timeout. The two directions are
/// concurrently polled `half_copy` futures (see its Rust note). The connection ends when both directions hit EOF, or,
/// with `idle_timeout` set, when no bytes flow in either direction for that long.
async fn pump<A, B>(downstream: A, upstream: B, idle_timeout: Option<Duration>, buffer_limit: u32)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (down_r, down_w) = tokio::io::split(downstream);
    let (up_r, up_w) = tokio::io::split(upstream);

    // Rust note: `Rc<Cell<Instant>>`, not an atomic, because this task is single-threaded (`!Send`, ADR-0003).
    let last_activity = Rc::new(Cell::new(Instant::now()));

    let both = async {
        tokio::join!(
            half_copy(down_r, up_w, last_activity.clone(), buffer_limit),
            half_copy(up_r, down_w, last_activity.clone(), buffer_limit),
        );
    };

    let Some(idle) = idle_timeout else {
        both.await;
        return;
    };

    // Idle timer: re-armed each time it fires early because activity pushed
    // `last_activity` forward, matching Envoy's per-connection idle timer.
    tokio::pin!(both);
    loop {
        let deadline = last_activity.get() + idle;
        tokio::select! {
            _ = &mut both => return,
            _ = tokio::time::sleep_until(deadline.into()) => {
                if last_activity.get().elapsed() >= idle {
                    return;
                }
                // Activity landed while we slept; loop and recompute deadline.
            }
        }
    }
}

/// Proxy one downstream connection to an upstream chosen from
/// `params.cluster`. Generic over `IO` so it serves both the plaintext accept
/// path (`TcpStream`) and the downstream-TLS path
/// (`tokio_rustls::server::TlsStream<TcpStream>`).
pub async fn proxy_connection<IO: AsyncRead + AsyncWrite + Unpin>(
    downstream: IO,
    snapshot: Arc<ConfigSnapshot>,
    params: TcpProxyParams,
    _guard: ConnectionGuard,
    mut shutdown: watch::Receiver<bool>,
) {
    let Some((host, port, connect_timeout)) = resolve_target(&snapshot, &params.cluster) else {
        tracing::warn!(cluster = %params.cluster, "tcp_proxy: cluster missing or has no priority-0 endpoints; closing connection");
        return;
    };

    let connect = connect_upstream(&host, port, connect_timeout, params.max_connect_attempts);
    let upstream = tokio::select! {
        result = connect => result,
        _ = shutdown.changed() => None,
    };

    let Some(upstream) = upstream else {
        tracing::debug!(cluster = %params.cluster, %host, port, "tcp_proxy: giving up on upstream connect");
        return;
    };

    tokio::select! {
        _ = pump(downstream, upstream, params.idle_timeout, params.buffer_limit) => {}
        // Drain hard-stop: end the connection promptly once the drain
        // deadline passes, same as the stub handler this replaces.
        _ = shutdown.changed() => {}
    }
}
