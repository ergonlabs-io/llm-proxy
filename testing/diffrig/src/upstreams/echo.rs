//! `echo`: reflects the received method, path, and headers as a JSON body,
//! and tags every response with `x-upstream-instance` so scenarios can tell
//! which instance answered. Every request is also appended to `log` for the
//! harness to assert on.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use serde_json::json;

use super::{record_request, serve, RequestLog, ServerHandle};

pub struct EchoUpstream {
    pub log: RequestLog,
    handle: ServerHandle,
}

impl EchoUpstream {
    pub fn addr(&self) -> SocketAddr {
        self.handle.addr
    }

    pub async fn spawn(instance_id: impl Into<String>) -> anyhow::Result<Self> {
        let log = RequestLog::new();
        let log_for_handler = log.clone();
        let instance_id = instance_id.into();
        let handle = serve(move |req: Request<Incoming>| {
            let log = log_for_handler.clone();
            let instance_id = instance_id.clone();
            async move { Ok(handle_echo(req, &log, &instance_id).await) }
        })
        .await?;
        Ok(Self { log, handle })
    }

    pub async fn shutdown(self) {
        self.handle.shutdown().await;
    }
}

async fn handle_echo(
    req: Request<Incoming>,
    log: &RequestLog,
    instance_id: &str,
) -> Response<Full<Bytes>> {
    let recorded = record_request(req, log).await;
    // Rust note: `BTreeMap` gives deterministic (sorted) key order in the
    // JSON body, which is nicer for assertions than a `HashMap`'s order.
    let headers_json: BTreeMap<_, _> = recorded.headers.iter().cloned().collect();
    let body = json!({
        "method": recorded.method,
        "path": recorded.path,
        "headers": headers_json,
    })
    .to_string();

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("x-upstream-instance", instance_id)
        .body(Full::new(Bytes::from(body)))
        .expect("response built from static, known-valid parts")
}

#[cfg(test)]
mod tests {
    use super::super::test_client;
    use super::*;

    #[tokio::test]
    async fn reflects_method_path_and_headers_and_records_the_request() {
        let echo = EchoUpstream::spawn("echo-1").await.expect("spawn echo");

        let res = test_client::send(
            echo.addr(),
            "GET",
            "/v1/models?x=1",
            &[("x-test-header", "hello")],
        )
        .await
        .expect("request should succeed");

        assert_eq!(res.status, 200);
        assert!(res
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("x-upstream-instance") && v == "echo-1"));

        let body: serde_json::Value = serde_json::from_str(&res.body).expect("valid json body");
        assert_eq!(body["method"], "GET");
        assert_eq!(body["path"], "/v1/models?x=1");
        assert_eq!(body["headers"]["x-test-header"], "hello");

        let recorded = echo.log.requests();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].method, "GET");
        assert_eq!(recorded[0].path, "/v1/models?x=1");
        assert!(recorded[0]
            .headers
            .iter()
            .any(|(k, v)| k == "x-test-header" && v == "hello"));

        echo.shutdown().await;
    }
}
