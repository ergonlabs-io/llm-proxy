//! `tcp_proxy` network filter runtime (WP-09): the first terminal L4 filter.
//! Given a matched downstream connection and its `TcpProxyConfig`, resolves
//! an upstream endpoint, connects, and pumps bytes bidirectionally until
//! either side closes, the connection idles out, or a drain shutdown fires.
//!
//! Cluster/endpoint resolution here is deliberately minimal (v1): "first
//! `priority == 0` endpoint" is a placeholder for the real load-balancing and
//! cluster-manager machinery landing in WP-16/WP-17.

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

/// Resolve an upstream target address for `cluster` from `snapshot`.
///
/// v1 endpoint selection: the first `priority == 0` endpoint, in declaration
/// order. `None` covers both "cluster missing" and "no priority-0 endpoints"
/// -- both are treated the same way by the caller (fail the connection).
///
/// TODO(WP-17): real load balancing (round robin / least request / ring hash
/// / random / maglev per `LbPolicy`); this always picks the same endpoint.
fn resolve_target(snapshot: &ConfigSnapshot, cluster: &str) -> Option<(String, u16, Duration)> {
    let cluster_ir = snapshot.clusters.get(cluster)?;
    let endpoint = cluster_ir.endpoints.iter().find(|e| e.priority == 0)?;
    Some((
        endpoint.host.clone(),
        endpoint.port,
        cluster_ir.connect_timeout,
    ))
}

/// Attempt to connect to `(host, port)` up to `max_attempts` times, each
/// bounded by `connect_timeout`. No backoff between attempts for v1 (Envoy's
/// `backoff_options` isn't represented in our IR yet).
///
/// Rust note: `(host, port)` implements `tokio::net::ToSocketAddrs`, which
/// resolves both IP literals (STATIC clusters) and DNS names
/// (STRICT_DNS/LOGICAL_DNS) through the system resolver -- so this connects
/// to DNS-named endpoints too, even though the full StrictDns
/// expansion/re-resolution semantics are WP-16's job, not this one's.
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

/// Copy one direction of the proxy: read from `r`, write to `w`, until `r`
/// hits EOF/error, then send FIN on `w` (`shutdown`). Bumps `last_activity`
/// on every read so the idle timer in [`pump`] sees traffic in either
/// direction.
///
/// Rust note: this is deliberately its *own* future (one per direction) rather
/// than two arms of a single `select!`. Two concurrently-polled halves are
/// what make the pump deadlock-free under bidirectional backpressure: if one
/// half is parked on a slow `write_all` (the peer isn't draining), the other
/// half still gets polled and keeps draining its own read side -- which is
/// often exactly what unblocks the stalled write. A single `select!` that
/// reads *and* writes inside one arm can't do that: selecting one arm parks
/// the whole task on that arm's write, starving the other direction (classic
/// proxy deadlock once both socket buffers fill).
async fn half_copy<R, W>(mut r: R, mut w: W, last_activity: Rc<Cell<Instant>>, buffer_limit: u32)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; buffer_limit.max(1) as usize];
    loop {
        match r.read(&mut buf).await {
            // EOF or read error: half-close -- send FIN on the write side so
            // the peer learns this direction is done, but let the *other*
            // direction (a separate `half_copy`) keep flowing.
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

/// Bidirectional pump with half-close (FIN propagation) and an optional idle
/// timeout. Runs the two directions as concurrently-polled `half_copy` futures
/// (see its Rust note for why concurrency, not a single `select!`, is what
/// keeps this deadlock-free). The whole connection ends when *both* directions
/// have hit EOF, or -- if `idle_timeout` is set -- when no bytes have flowed in
/// either direction for that long.
async fn pump<A, B>(downstream: A, upstream: B, idle_timeout: Option<Duration>, buffer_limit: u32)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (down_r, down_w) = tokio::io::split(downstream);
    let (up_r, up_w) = tokio::io::split(upstream);

    // Rust note: `Rc<Cell<Instant>>` (not an atomic) because this whole task
    // is single-threaded (`!Send` per ADR-0003); each direction owns a clone
    // and bumps it on read, the idle branch below reads it.
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
