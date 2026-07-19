//! `slow`: records the request like `echo`, then waits a configurable delay
//! before responding 200 — used to exercise timeout/backpressure behavior.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};

use super::{record_request, serve, RequestLog, ServerHandle};

pub struct SlowUpstream {
    pub log: RequestLog,
    handle: ServerHandle,
}

impl SlowUpstream {
    pub fn addr(&self) -> SocketAddr {
        self.handle.addr
    }

    pub async fn spawn(delay: Duration) -> anyhow::Result<Self> {
        let log = RequestLog::new();
        let log_for_handler = log.clone();
        let handle = serve(move |req: Request<Incoming>| {
            let log = log_for_handler.clone();
            async move { Ok(handle_slow(req, &log, delay).await) }
        })
        .await?;
        Ok(Self { log, handle })
    }

    pub async fn shutdown(self) {
        self.handle.shutdown().await;
    }
}

async fn handle_slow(
    req: Request<Incoming>,
    log: &RequestLog,
    delay: Duration,
) -> Response<Full<Bytes>> {
    record_request(req, log).await;
    tokio::time::sleep(delay).await;
    Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::from_static(b"slow-ok")))
        .expect("response built from static, known-valid parts")
}

#[cfg(test)]
mod tests {
    use super::super::test_client;
    use super::*;

    #[tokio::test]
    async fn delays_at_least_the_configured_duration() {
        let delay = Duration::from_millis(150);
        let slow = SlowUpstream::spawn(delay).await.expect("spawn slow");

        let started = tokio::time::Instant::now();
        let res = test_client::send(slow.addr(), "GET", "/", &[])
            .await
            .expect("request should succeed");
        let elapsed = started.elapsed();

        assert_eq!(res.status, 200);
        assert!(
            elapsed >= delay,
            "expected at least {delay:?}, got {elapsed:?}"
        );
        assert_eq!(slow.log.requests().len(), 1);

        slow.shutdown().await;
    }
}
