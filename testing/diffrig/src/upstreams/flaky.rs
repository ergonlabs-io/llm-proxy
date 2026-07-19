//! `flaky`: records each request like `echo`/`slow`, but its response is
//! driven by a scripted [`FailScript`] consumed one [`Action`] per request
//! (in connection order); the last action repeats forever once the script
//! is exhausted. Unlike `echo`/`slow` this speaks raw HTTP/1.1 by hand
//! instead of going through hyper's server, since `Action::Reset` and
//! `Action::TimeoutMs` need to close the socket without ever writing a
//! response — something a `hyper::service::Service` can't do mid-connection.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use super::{RecordedRequest, RequestLog};

/// One scripted action a `FlakyUpstream` takes for a request, consumed in
/// order (last one repeats once the script runs out).
///
/// Rust note: default (externally tagged) `serde::Deserialize` turns
/// `Respond(u16)` into YAML `respond: 503`, the unit variant `Reset` into
/// the bare scalar `reset`, and `TimeoutMs(u64)` into `timeout_ms: 200` —
/// no extra serde attributes needed.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Respond with this status code and an empty body.
    Respond(u16),
    /// Drop the connection immediately without writing a response
    /// (simulates a connection reset).
    Reset,
    /// Hold the connection open for this many milliseconds, then drop it
    /// without responding (simulates a hung/timed-out upstream).
    TimeoutMs(u64),
}

/// Ordered list of [`Action`]s a `FlakyUpstream` walks through, one per
/// accepted connection; repeats the final action forever once exhausted.
#[derive(Debug, Clone)]
pub struct FailScript(Vec<Action>);

impl FailScript {
    pub fn new(actions: Vec<Action>) -> Self {
        assert!(
            !actions.is_empty(),
            "FailScript must have at least one action"
        );
        Self(actions)
    }

    fn action_for(&self, attempt: usize) -> &Action {
        // Rust note: `.min(len - 1)` clamps to the last index so the script
        // "sticks" on its final action instead of panicking once exhausted.
        &self.0[attempt.min(self.0.len() - 1)]
    }
}

pub struct FlakyUpstream {
    pub log: RequestLog,
    addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl FlakyUpstream {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub async fn spawn(script: FailScript) -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let log = RequestLog::new();
        let log_for_task = log.clone();
        let attempt = Arc::new(Mutex::new(0usize));
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { continue };
                        let script = script.clone();
                        let log = log_for_task.clone();
                        let attempt = Arc::clone(&attempt);
                        tokio::spawn(async move {
                            let idx = {
                                let mut guard = attempt.lock().expect("attempt counter poisoned");
                                let idx = *guard;
                                *guard += 1;
                                idx
                            };
                            let action = script.action_for(idx).clone();
                            handle_connection(stream, &log, action).await;
                        });
                    }
                }
            }
        });

        Ok(Self {
            log,
            addr,
            shutdown_tx: Some(shutdown_tx),
            task,
        })
    }

    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        let _ = self.task.await;
    }
}

async fn handle_connection(mut stream: TcpStream, log: &RequestLog, action: Action) {
    let Some(recorded) = read_request(&mut stream).await else {
        return;
    };
    log.record(recorded);

    match action {
        Action::Respond(status) => {
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                reason = status_reason(status)
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
        Action::Reset => {
            // Rust note: dropping the stream without writing anything closes
            // the socket; the client observes an error/EOF instead of a
            // response.
            drop(stream);
        }
        Action::TimeoutMs(ms) => {
            tokio::time::sleep(Duration::from_millis(ms)).await;
            drop(stream);
        }
    }
}

/// Minimal HTTP/1.1 request-line + header parse — just enough to record
/// method/path/headers/body length for a scripted test upstream. No
/// chunked-encoding or pipelining support: differential scenarios that
/// exercise `flaky` send one simple request per connection.
async fn read_request(stream: &mut TcpStream) -> Option<RecordedRequest> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > 64 * 1024 {
            return None;
        }
    };

    let header_text = std::str::from_utf8(&buf[..header_end]).ok()?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split(' ');
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();

    let mut headers = Vec::new();
    let mut content_length = 0usize;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':')?;
        let name = name.trim().to_string();
        let value = value.trim().to_string();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().unwrap_or(0);
        }
        headers.push((name, value));
    }

    let already_read = buf.len() - (header_end + 4);
    let mut body_len = already_read;
    let mut remaining = content_length.saturating_sub(already_read);
    while remaining > 0 {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        let taken = n.min(remaining);
        body_len += taken;
        remaining -= taken;
    }

    Some(RecordedRequest {
        method,
        path,
        headers,
        body_len,
    })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn send_request(addr: SocketAddr) -> anyhow::Result<TcpStream> {
        let mut stream = TcpStream::connect(addr).await?;
        stream
            .write_all(b"GET /v1/chat/completions HTTP/1.1\r\nhost: test\r\n\r\n")
            .await?;
        Ok(stream)
    }

    async fn read_status_line(stream: &mut TcpStream) -> Option<String> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 256];
        loop {
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                return if buf.is_empty() {
                    None
                } else {
                    Some(String::from_utf8_lossy(&buf).to_string())
                };
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(2).any(|w| w == b"\r\n") {
                return Some(String::from_utf8_lossy(&buf).to_string());
            }
        }
    }

    #[tokio::test]
    async fn follows_the_script_in_order_then_repeats_the_last_action() {
        let script = FailScript::new(vec![
            Action::Respond(503),
            Action::Respond(503),
            Action::Respond(200),
        ]);
        let flaky = FlakyUpstream::spawn(script).await.expect("spawn flaky");

        for expected_status in ["503", "503", "200", "200"] {
            let mut stream = send_request(flaky.addr()).await.expect("connect+send");
            let response = read_status_line(&mut stream)
                .await
                .expect("some response bytes");
            assert!(
                response.starts_with(&format!("HTTP/1.1 {expected_status}")),
                "expected status {expected_status}, got: {response}"
            );
        }

        let recorded = flaky.log.requests();
        assert_eq!(recorded.len(), 4);
        assert!(recorded.iter().all(|r| r.method == "GET"));
        assert!(recorded.iter().all(|r| r.path == "/v1/chat/completions"));

        flaky.shutdown().await;
    }

    #[tokio::test]
    async fn reset_action_closes_the_connection_without_a_response() {
        let flaky = FlakyUpstream::spawn(FailScript::new(vec![Action::Reset]))
            .await
            .expect("spawn flaky");

        let mut stream = send_request(flaky.addr()).await.expect("connect+send");
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.expect("read should not error");
        assert_eq!(n, 0, "expected EOF with no response bytes");
        assert_eq!(flaky.log.requests().len(), 1);

        flaky.shutdown().await;
    }

    #[tokio::test]
    async fn timeout_ms_action_holds_the_connection_then_closes() {
        let delay = Duration::from_millis(100);
        let flaky = FlakyUpstream::spawn(FailScript::new(vec![Action::TimeoutMs(100)]))
            .await
            .expect("spawn flaky");

        let mut stream = send_request(flaky.addr()).await.expect("connect+send");
        let started = tokio::time::Instant::now();
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.expect("read should not error");
        let elapsed = started.elapsed();

        assert_eq!(n, 0, "expected EOF with no response bytes");
        assert!(
            elapsed >= delay,
            "expected at least {delay:?}, got {elapsed:?}"
        );

        flaky.shutdown().await;
    }
}
