//! The byte pump behind an accepted upgrade (envoy-semantics.md S10.2).
//!
//! Upstream bytes go through the stream's encode filter chain: the tunnel
//! feeds them into the `101` response's body ([`UpgradePayloadSender`]) and
//! writes what the chain emits to the client. Client bytes go straight to
//! the upstream (`internal-docs/envoy-divergences.md`). When the upstream
//! closes, the body ends, so the encode chain's end of stream, the access
//! log and the request record run at the tunnel's close. A tunnel torn down
//! early drops the body unfinished, which takes the filter chain's
//! partial-stream path.
//!
//! On drain a WebSocket tunnel sends the client a Close frame with code 1001
//! between two frames, and stops forwarding upstream frames after it. The
//! client's own Close reply goes to the upstream as ordinary client bytes,
//! so both peers finish the closing handshake (S10.5, an llm-proxy
//! extension).

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::handler::{StreamBody, UpgradePayloadSender};
use crate::websocket::{close_frame, FrameDecoder, CLOSE_GOING_AWAY};

const READ_BUF: usize = 8192;

/// Drain state shared by every tunnel of one downstream connection.
///
/// Rust note: `Rc`/`Cell`, not `Arc`/atomics: one connection lives on one
/// worker thread (ADR-0003).
#[derive(Clone, Default)]
pub(crate) struct DrainSignal(Rc<DrainInner>);

#[derive(Default)]
struct DrainInner {
    started: Cell<bool>,
    notify: Notify,
}

impl DrainSignal {
    pub(crate) fn start(&self) {
        self.0.started.set(true);
        self.0.notify.notify_waiters();
    }

    async fn started(&self) {
        // Rust note: check-then-`notified()` is race-free on a
        // current-thread runtime: nothing can call `start` between the check
        // and the first poll that registers this waiter.
        while !self.0.started.get() {
            self.0.notify.notified().await;
        }
    }
}

/// What one tunnel needs besides its two byte streams.
pub(crate) struct TunnelParts {
    pub payload: UpgradePayloadSender,
    pub body: StreamBody,
    pub websocket: bool,
    pub drain: DrainSignal,
    pub idle_timeout: Duration,
}

/// Why a direction stopped early. Logged at debug; the tunnel then ends.
enum Stop {
    Io(std::io::Error),
    BodyGone,
    BodyError,
}

impl std::fmt::Display for Stop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Stop::Io(err) => write!(f, "i/o error: {err}"),
            Stop::BodyGone => f.write_str("the response body was dropped"),
            Stop::BodyError => f.write_str("the response body failed"),
        }
    }
}

/// Run the tunnel until both directions finish, one fails, or no byte moved
/// in either direction for `idle_timeout`.
pub(crate) async fn run<D, U>(downstream: D, upstream: U, parts: TunnelParts)
where
    D: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let TunnelParts {
        payload,
        body,
        websocket,
        drain,
        idle_timeout,
    } = parts;
    let (down_read, down_write) = tokio::io::split(downstream);
    let (up_read, up_write) = tokio::io::split(upstream);
    let activity = Cell::new(Instant::now());

    let client_to_upstream = copy_raw(down_read, up_write, &activity);
    let upstream_to_chain = feed_chain(up_read, payload, &activity);
    let chain_to_client = drain_chain(body, down_write, websocket, &drain, &activity);
    let all = async { tokio::try_join!(client_to_upstream, upstream_to_chain, chain_to_client) };

    tokio::select! {
        result = all => {
            if let Err(stop) = result {
                tracing::debug!(%stop, "upgrade tunnel: a direction stopped early");
            }
        }
        () = idle(&activity, idle_timeout) => {
            tracing::debug!(?idle_timeout, "upgrade tunnel: idle timeout, tearing down");
        }
    }
    // Every future above is dropped here, the response body with them. A
    // body that already ended has finished its stream; one that did not is
    // recorded as cut.
}

/// Resolves once `activity` is `idle_timeout` in the past.
async fn idle(activity: &Cell<Instant>, idle_timeout: Duration) {
    loop {
        let deadline = activity.get() + idle_timeout;
        tokio::time::sleep_until(deadline).await;
        if activity.get() + idle_timeout <= Instant::now() {
            return;
        }
    }
}

/// Client to upstream, byte for byte. A clean EOF half-closes the upstream.
async fn copy_raw<R, W>(mut from: R, mut to: W, activity: &Cell<Instant>) -> Result<(), Stop>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; READ_BUF];
    loop {
        let n = from.read(&mut buf).await.map_err(Stop::Io)?;
        if n == 0 {
            // The other directions keep running; a failed half-close is not a
            // reason to cut them.
            if let Err(err) = to.shutdown().await {
                tracing::debug!(error = %err, "upgrade tunnel: half-close after client EOF failed");
            }
            return Ok(());
        }
        to.write_all(&buf[..n]).await.map_err(Stop::Io)?;
        to.flush().await.map_err(Stop::Io)?;
        activity.set(Instant::now());
    }
}

/// Upstream into the response body. Dropping `payload` on EOF ends the body.
async fn feed_chain<R>(
    mut from: R,
    payload: UpgradePayloadSender,
    activity: &Cell<Instant>,
) -> Result<(), Stop>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; READ_BUF];
    loop {
        let n = from.read(&mut buf).await.map_err(Stop::Io)?;
        if n == 0 {
            return Ok(());
        }
        activity.set(Instant::now());
        payload
            .send(Bytes::copy_from_slice(&buf[..n]))
            .await
            .map_err(|_| Stop::BodyGone)?;
    }
}

/// The encode chain's output to the client, with the drain Close.
async fn drain_chain<W>(
    mut body: StreamBody,
    mut to: W,
    websocket: bool,
    drain: &DrainSignal,
    activity: &Cell<Instant>,
) -> Result<(), Stop>
where
    W: AsyncWrite + Unpin,
{
    let mut frames = FrameDecoder::default();
    let mut close_wanted = false;
    let mut close_sent = false;
    loop {
        tokio::select! {
            () = drain.started(), if websocket && !close_wanted => {
                close_wanted = true;
                if frames.at_boundary() {
                    send_close(&mut to).await?;
                    close_sent = true;
                }
            }
            frame = body.frame() => {
                let Some(frame) = frame else {
                    if let Err(err) = to.shutdown().await {
                        tracing::debug!(error = %err, "upgrade tunnel: close toward the client failed");
                    }
                    return Ok(());
                };
                let Ok(data) = frame.map_err(|_| Stop::BodyError)?.into_data() else {
                    continue;
                };
                activity.set(Instant::now());
                if close_sent {
                    // After a Close the client may receive no other frame
                    // (RFC 6455 section 5.5.1). The bytes still went through
                    // the chain, so they are still metered.
                    continue;
                }
                if close_wanted {
                    let used = frames.finish_frame(&data);
                    to.write_all(&data[..used]).await.map_err(Stop::Io)?;
                    if frames.at_boundary() {
                        send_close(&mut to).await?;
                        close_sent = true;
                    }
                } else {
                    if websocket {
                        frames.feed(&data, &mut |_| {});
                    }
                    to.write_all(&data).await.map_err(Stop::Io)?;
                }
                to.flush().await.map_err(Stop::Io)?;
            }
        }
    }
}

async fn send_close<W: AsyncWrite + Unpin>(to: &mut W) -> Result<(), Stop> {
    to.write_all(&close_frame(CLOSE_GOING_AWAY, "server draining"))
        .await
        .map_err(Stop::Io)?;
    to.flush().await.map_err(Stop::Io)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::handler::{local_boxed, upgrade_payload_channel, BodyError};
    use crate::websocket::opcode;

    /// A tunnel whose encode chain is a pass-through that records every
    /// chunk and whether the body reached its end.
    struct Rig {
        seen: Rc<RefCell<Vec<u8>>>,
        ended: Rc<Cell<bool>>,
        parts: TunnelParts,
    }

    struct Recording {
        inner: StreamBody,
        seen: Rc<RefCell<Vec<u8>>>,
        ended: Rc<Cell<bool>>,
    }

    impl hyper::body::Body for Recording {
        type Data = Bytes;
        type Error = BodyError;
        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, BodyError>>> {
            let polled = self.inner.as_mut().poll_frame(cx);
            match &polled {
                std::task::Poll::Ready(Some(Ok(frame))) => {
                    if let Some(data) = frame.data_ref() {
                        self.seen.borrow_mut().extend_from_slice(data);
                    }
                }
                std::task::Poll::Ready(None) => self.ended.set(true),
                _ => {}
            }
            polled
        }
    }

    fn rig(websocket: bool, idle_timeout: Duration, drain: DrainSignal) -> Rig {
        let (payload, inner) = upgrade_payload_channel();
        let seen = Rc::new(RefCell::new(Vec::new()));
        let ended = Rc::new(Cell::new(false));
        let body = local_boxed(Recording {
            inner,
            seen: seen.clone(),
            ended: ended.clone(),
        });
        Rig {
            seen,
            ended,
            parts: TunnelParts {
                payload,
                body,
                websocket,
                drain,
                idle_timeout,
            },
        }
    }

    fn text_frame(payload: &[u8]) -> Vec<u8> {
        assert!(payload.len() < 126);
        let mut out = vec![0x80 | opcode::TEXT, payload.len() as u8];
        out.extend_from_slice(payload);
        out
    }

    async fn local<F: std::future::Future>(f: F) -> F::Output {
        tokio::task::LocalSet::new().run_until(f).await
    }

    /// A stalled tunnel -- nothing written on either side -- must be torn
    /// down once `idle_timeout` elapses with no activity at all.
    #[tokio::test]
    async fn idle_tunnel_is_torn_down_after_idle_window() {
        local(async {
            let (down, _down_test) = tokio::io::duplex(1024);
            let (up, _up_test) = tokio::io::duplex(1024);
            let idle = Duration::from_millis(100);
            let rig = rig(false, idle, DrainSignal::default());
            tokio::time::timeout(idle * 5, run(down, up, rig.parts))
                .await
                .expect("idle tunnel must be torn down by the idle timeout, not hang forever");
            assert!(
                !rig.ended.get(),
                "an idle teardown is a cut, not a clean end"
            );
        })
        .await;
    }

    /// ANY byte in EITHER direction resets the idle timer, so a tunnel
    /// carrying periodic traffic is not torn down mid-conversation.
    #[tokio::test]
    async fn activity_resets_idle_timer() {
        local(async {
            let (down, mut down_test) = tokio::io::duplex(1024);
            let (up, mut up_test) = tokio::io::duplex(1024);
            let idle = Duration::from_millis(100);
            let rig = rig(false, idle, DrainSignal::default());
            let pump = tokio::task::spawn_local(run(down, up, rig.parts));

            // One byte every ~40ms for ~280ms: more than `idle` since the
            // tunnel opened, so a timer that did not reset would have fired.
            let sent: Vec<u8> = (0u8..7).collect();
            for &byte in &sent {
                down_test.write_all(&[byte]).await.expect("write");
                tokio::time::sleep(Duration::from_millis(40)).await;
            }
            assert!(!pump.is_finished(), "pump must not tear down while active");

            let mut received = vec![0u8; sent.len()];
            tokio::time::timeout(Duration::from_secs(1), up_test.read_exact(&mut received))
                .await
                .expect("timed out reading forwarded bytes")
                .expect("read forwarded bytes");
            assert_eq!(received, sent);

            tokio::time::timeout(idle * 5, pump)
                .await
                .expect("pump must tear down once activity stops")
                .expect("pump task must not panic");
        })
        .await;
    }

    /// Upstream bytes reach the client through the encode chain, and the
    /// body ends when the upstream closes: the stream completes at the
    /// tunnel's close, promptly, not by the idle timer.
    #[tokio::test]
    async fn clean_close_runs_upstream_bytes_through_the_chain_and_ends_the_body() {
        local(async {
            let (down, mut down_test) = tokio::io::duplex(1024);
            let (up, mut up_test) = tokio::io::duplex(1024);
            let rig = rig(false, Duration::from_secs(10), DrainSignal::default());
            let pump = tokio::task::spawn_local(run(down, up, rig.parts));

            down_test.write_all(b"hello").await.expect("client write");
            down_test.shutdown().await.expect("client close");
            let mut received = [0u8; 5];
            up_test
                .read_exact(&mut received)
                .await
                .expect("upstream read");
            assert_eq!(&received, b"hello");
            let mut eof = [0u8; 1];
            assert_eq!(up_test.read(&mut eof).await.expect("eof"), 0);

            up_test.write_all(b"world").await.expect("upstream write");
            up_test.shutdown().await.expect("upstream close");
            let mut back = Vec::new();
            down_test.read_to_end(&mut back).await.expect("client read");
            assert_eq!(back, b"world");

            tokio::time::timeout(Duration::from_millis(500), pump)
                .await
                .expect("clean close must finish promptly")
                .expect("pump task must not panic");
            assert_eq!(
                &*rig.seen.borrow(),
                b"world",
                "the chain saw the upstream bytes"
            );
            assert!(
                rig.ended.get(),
                "the body reached its end at the tunnel's close"
            );
        })
        .await;
    }

    /// Drain mid-frame: the frame in flight completes, then the client gets
    /// Close 1001 and nothing after it, while the chain still sees every
    /// upstream byte (so it is still metered).
    #[tokio::test]
    async fn drain_sends_close_1001_after_the_frame_in_flight() {
        local(async {
            let (down, mut down_test) = tokio::io::duplex(4096);
            let (up, mut up_test) = tokio::io::duplex(4096);
            let drain = DrainSignal::default();
            let rig = rig(true, Duration::from_secs(10), drain.clone());
            let pump = tokio::task::spawn_local(run(down, up, rig.parts));

            let first = text_frame(b"first-frame");
            let after = text_frame(b"after-close");
            up_test.write_all(&first[..5]).await.expect("half a frame");
            // Wait until the half frame reached the client, so the drain
            // lands mid-frame.
            let mut head = [0u8; 5];
            down_test.read_exact(&mut head).await.expect("half frame");
            drain.start();
            tokio::task::yield_now().await;
            up_test.write_all(&first[5..]).await.expect("rest of frame");
            up_test.write_all(&after).await.expect("next frame");
            up_test.shutdown().await.expect("upstream close");

            let mut rest = Vec::new();
            down_test.read_to_end(&mut rest).await.expect("client read");
            let mut client = head.to_vec();
            client.extend_from_slice(&rest);
            let mut expected = first.clone();
            expected.extend(close_frame(CLOSE_GOING_AWAY, "server draining"));
            assert_eq!(client, expected);

            // The client answers the Close and closes its side.
            down_test.shutdown().await.expect("client close");
            tokio::time::timeout(Duration::from_millis(500), pump)
                .await
                .expect("tunnel ends once both peers close")
                .expect("pump task must not panic");
            let mut chain = first;
            chain.extend(after);
            assert_eq!(*rig.seen.borrow(), chain);
        })
        .await;
    }

    /// A non-WebSocket upgrade is an opaque byte stream: drain never writes
    /// a frame into it.
    #[tokio::test]
    async fn drain_leaves_a_non_websocket_tunnel_untouched() {
        local(async {
            let (down, mut down_test) = tokio::io::duplex(1024);
            let (up, mut up_test) = tokio::io::duplex(1024);
            let drain = DrainSignal::default();
            let rig = rig(false, Duration::from_secs(10), drain.clone());
            let pump = tokio::task::spawn_local(run(down, up, rig.parts));
            drain.start();
            up_test.write_all(b"raw").await.expect("write");
            up_test.shutdown().await.expect("close");
            down_test.shutdown().await.expect("close");
            let mut back = Vec::new();
            down_test.read_to_end(&mut back).await.expect("read");
            assert_eq!(back, b"raw");
            pump.await.expect("no panic");
        })
        .await;
    }

    /// The body erroring is a cut: the tunnel stops instead of spinning.
    #[tokio::test]
    async fn a_failing_body_stops_the_tunnel() {
        local(async {
            let (down, _down_test) = tokio::io::duplex(1024);
            let (up, _up_test) = tokio::io::duplex(1024);
            let (payload, _) = upgrade_payload_channel();
            struct Failing;
            impl hyper::body::Body for Failing {
                type Data = Bytes;
                type Error = BodyError;
                fn poll_frame(
                    self: std::pin::Pin<&mut Self>,
                    _cx: &mut std::task::Context<'_>,
                ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, BodyError>>>
                {
                    std::task::Poll::Ready(Some(Err(BodyError::Upstream("boom".into()))))
                }
            }
            let body = local_boxed(Failing);
            let parts = TunnelParts {
                payload,
                body,
                websocket: true,
                drain: DrainSignal::default(),
                idle_timeout: Duration::from_secs(10),
            };
            tokio::time::timeout(Duration::from_secs(1), run(down, up, parts))
                .await
                .expect("a body error ends the tunnel");
        })
        .await;
    }
}
