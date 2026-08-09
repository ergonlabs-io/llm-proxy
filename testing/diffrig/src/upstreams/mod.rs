//! Shared, in-process test upstreams used by differential scenarios and the
//! rig's own self-tests: an `echo` server that reflects what it received, a
//! `flaky` server driven by a scripted fail sequence, and a `slow` server
//! that delays before responding. All bind an ephemeral port
//! (`127.0.0.1:0`) and hand back their bound address plus a request log the
//! test harness can query.

mod anthropic;
mod echo;
mod flaky;
mod openai;
mod slow;
mod tls_support;

pub use anthropic::{AnthropicConfig, AnthropicUpstream, MessagesRequestLog};
pub use echo::EchoUpstream;
pub use flaky::{Action, FailScript, FlakyUpstream};
pub use openai::{ChatRequestLog, OpenAiConfig, OpenAiUpstream};
pub use slow::SlowUpstream;
pub use tls_support::{spawn_tls_passthrough, MockTls, TlsPassthrough};

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// One HTTP request as observed by an upstream, recorded for assertions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    /// Rust note: header order is preserved (`Vec`, not a map) since HTTP
    /// allows repeated header names and callers may want to assert on order.
    pub headers: Vec<(String, String)>,
    pub body_len: usize,
}

/// Thread-safe, append-only log of requests an upstream has received.
///
/// Rust note: `Arc<Mutex<..>>` gives shared ownership between the server
/// task(s) and the test/harness code holding the handle; a `std::sync::Mutex`
/// is fine here since we only ever hold the lock for a plain `Vec` push/clone,
/// never across an `.await`.
#[derive(Debug, Clone, Default)]
pub struct RequestLog(Arc<Mutex<Vec<RecordedRequest>>>);

impl RequestLog {
    pub fn new() -> Self {
        Self::default()
    }

    fn record(&self, req: RecordedRequest) {
        self.0.lock().expect("request log mutex poisoned").push(req);
    }

    /// Snapshot of every request received so far, in arrival order.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.0.lock().expect("request log mutex poisoned").clone()
    }
}

/// Handle to a spawned in-process HTTP upstream: its bound address and a
/// clean shutdown switch. Awaiting `shutdown()` stops accepting new
/// connections and joins the accept-loop task.
pub(crate) struct ServerHandle {
    pub(crate) addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl ServerHandle {
    pub(crate) async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            // Rust note: the receiver may already be gone if the accept
            // loop exited on its own; a dropped-receiver send error is not
            // interesting here.
            let _ = tx.send(());
        }
        let _ = self.task.await;
    }
}

/// Response body type every upstream in this module hands back to `serve`.
///
/// Rust note: `BoxBody` (from `http_body_util::combinators`) type-erases the
/// concrete `Body` implementation behind a `Box<dyn Body>`-like wrapper, so
/// `echo`/`slow` (a single, already-buffered `Full<Bytes>`) and `openai`
/// (a paced `StreamBody` fed from a `futures::stream::unfold`) can share one
/// `serve` function despite having unrelated concrete body types — each just
/// calls `.boxed()` before returning.
pub(crate) type ResponseBody = BoxBody<Bytes, std::convert::Infallible>;

/// Spawn a hyper HTTP/1.1 server bound to an ephemeral loopback port, calling
/// `handler` for every request on every accepted connection.
///
/// Rust note: `F` is a `Clone + Send + Sync` closure factory (one clone per
/// connection) rather than a `Fn` returning a shared `Service`, because hyper
/// wants a fresh `Service` per connection; cloning a cheap handler is the
/// idiomatic way to hand each connection its own.
pub(crate) async fn serve<F, Fut>(handler: F) -> anyhow::Result<ServerHandle>
where
    F: Fn(Request<Incoming>) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<Response<ResponseBody>, std::convert::Infallible>>
        + Send
        + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { continue };
                    let io = TokioIo::new(stream);
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        let service = service_fn(handler);
                        let _ = http1::Builder::new().serve_connection(io, service).await;
                    });
                }
            }
        }
    });

    Ok(ServerHandle {
        addr,
        shutdown_tx: Some(shutdown_tx),
        task,
    })
}

/// Extract method/path/headers/body from a request and append the recorded
/// shape (not the raw bytes — see `body_len`) to `log`, returning both the
/// recorded copy and the collected body so callers that need to look inside
/// the body (e.g. `openai`, to parse JSON) don't have to re-read the request.
pub(crate) async fn record_request_with_body(
    req: Request<Incoming>,
    log: &RequestLog,
) -> (RecordedRequest, Bytes) {
    let method = req.method().to_string();
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.to_string(),
                value.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let body_bytes = req
        .into_body()
        .collect()
        .await
        .map(|collected| collected.to_bytes())
        .unwrap_or_default();

    let recorded = RecordedRequest {
        method,
        path,
        headers,
        body_len: body_bytes.len(),
    };
    log.record(recorded.clone());
    (recorded, body_bytes)
}

/// Extract method/path/headers/body-length from a request and append it to
/// `log`, returning the recorded copy so the caller (e.g. `echo`) can build a
/// response from it without re-reading the request.
pub(crate) async fn record_request(req: Request<Incoming>, log: &RequestLog) -> RecordedRequest {
    record_request_with_body(req, log).await.0
}

// --- shared SSE framing/pacing ----------------------------------------------
//
// `openai` (chat completions + Responses API) and `anthropic` (messages) each
// stream Server-Sent Events, differing only in whether a frame carries a
// named `event:` line and in exactly what pacing schedule they build. The
// framing and the paced delivery itself are identical, so both live here once
// instead of three times.

/// Render a data-only SSE frame (OpenAI chat-completions style): just a
/// `data:` line and the blank-line terminator.
pub(crate) fn sse_data_frame(payload: &str) -> String {
    format!("data: {payload}\n\n")
}

/// Render a named SSE frame (Anthropic messages, OpenAI Responses API style):
/// an `event:` line naming the event type, then the `data:` line.
pub(crate) fn sse_named_frame(event: &str, payload: &str) -> String {
    format!("event: {event}\ndata: {payload}\n\n")
}

/// Turn a schedule of `(delay-before-this-frame, already-rendered frame
/// text)` pairs into a paced `ResponseBody`.
///
/// Rust note: `futures::stream::unfold` builds a `Stream` from a seed (here,
/// "how far through `frames` are we") plus an async step function; hyper's
/// `StreamBody` then polls that stream and writes each item out as an
/// HTTP/1.1 chunk as soon as it's ready, which is what gives real (not
/// buffered) pacing. This is the same approach `openai`'s chat-completions
/// streaming used before it was factored out to be shared.
pub(crate) fn paced_sse_body(frames: Vec<(Duration, String)>) -> ResponseBody {
    let stream = futures::stream::unfold((0usize, frames), |(i, frames)| async move {
        let (delay, payload) = frames.get(i)?.clone();
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        let event = Bytes::from(payload);
        Some((
            Ok::<_, std::convert::Infallible>(Frame::data(event)),
            (i + 1, frames),
        ))
    });
    StreamBody::new(stream).boxed()
}

#[cfg(test)]
pub(crate) mod test_client {
    //! Minimal HTTP/1.1 client built directly on `hyper`'s connection API
    //! (no pooling, one request per connection) — just enough to drive the
    //! in-crate upstream tests without adding another HTTP client dependency.

    use bytes::Bytes;
    use http_body_util::{BodyExt, Empty};
    use hyper::client::conn::http1;
    use hyper::Request;
    use hyper_util::rt::TokioIo;
    use std::net::SocketAddr;
    use tokio::net::TcpStream;

    pub struct RawResponse {
        pub status: u16,
        pub headers: Vec<(String, String)>,
        pub body: String,
    }

    /// Send a bodyless request with the given headers and collect the
    /// response. Returns an error if the connection is reset or refused.
    pub async fn send(
        addr: SocketAddr,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
    ) -> anyhow::Result<RawResponse> {
        let stream = TcpStream::connect(addr).await?;
        let io = TokioIo::new(stream);
        let (mut sender, conn) = http1::handshake(io).await?;
        // Rust note: hyper 1.x splits a connection into a `sender` handle and
        // a `conn` future that must be polled for I/O to actually happen;
        // spawning it is the standard pattern for a fire-and-forget driver.
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let mut builder = Request::builder().method(method).uri(path);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let req = builder.body(Empty::<Bytes>::new())?;

        let res = sender.send_request(req).await?;
        let status = res.status().as_u16();
        let response_headers = res
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.to_string(),
                    value.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        let body_bytes = res.into_body().collect().await?.to_bytes();
        let body = String::from_utf8_lossy(&body_bytes).to_string();

        Ok(RawResponse {
            status,
            headers: response_headers,
            body,
        })
    }
}
