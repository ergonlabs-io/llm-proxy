//! Bounded authorization v3 transport. Generated messages never cross this module.
use prost::Message;
use proxy_api::envoy::{config::core::v3 as core, service::auth::v3 as auth};
use proxy_config::authorization::*;
use std::{
    error::Error,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};
use tokio::sync::Semaphore;
use tonic::transport::{Channel, Endpoint};

pub struct GrpcAuthorizationClient {
    channel: Channel,
    permits: Arc<Semaphore>,
    timeout: Duration,
}

impl GrpcAuthorizationClient {
    pub fn new(address: SocketAddr, timeout: Duration, connect_timeout: Duration) -> Self {
        let channel = Endpoint::from_shared(format!("http://{address}"))
            .expect("socket endpoint")
            .connect_timeout(connect_timeout.min(timeout))
            .buffer_size(1)
            .connect_lazy();
        Self {
            channel,
            permits: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
            timeout,
        }
    }
}

fn error(kind: AuthorizationError) -> AuthorizationResult {
    AuthorizationResult {
        decision: AuthorizationDecision::Error(kind),
        ignored_metadata: false,
    }
}

impl AuthorizationClient for GrpcAuthorizationClient {
    fn check(&self, request: AuthorizationRequest) -> AuthorizationFuture {
        let permit = self.permits.clone().try_acquire_owned();
        let channel = self.channel.clone();
        let timeout = self.timeout;
        Box::pin(async move {
            let Ok(_permit) = permit else {
                return error(AuthorizationError::Saturation);
            };
            let request = encode_request(request);
            if request.encoded_len() > MAX_MESSAGE_BYTES {
                // The client controls header size, so this must never look like
                // a service outage (the filter denies it even under fail-open).
                return error(AuthorizationError::RequestTooLarge);
            }
            let mut client = auth::authorization_client::AuthorizationClient::new(channel)
                .max_decoding_message_size(MAX_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_MESSAGE_BYTES);
            let mut request = tonic::Request::new(request);
            request.set_timeout(timeout);
            let started = tokio::time::Instant::now();
            match tokio::time::timeout(timeout, client.check(request)).await {
                Err(_) => error(AuthorizationError::Timeout),
                // The service enforces the same `grpc-timeout` and may answer
                // first (tonic sends CANCELLED, without the source error). Under
                // load that answer can be ready when this task wakes, and
                // `timeout` polls the call before its timer, so judge by our
                // own deadline rather than by which side noticed it first.
                Ok(Err(s)) => error(if is_timeout(&s) || started.elapsed() >= timeout {
                    AuthorizationError::Timeout
                } else {
                    AuthorizationError::Transport
                }),
                Ok(Ok(response)) => decode_response(response.into_inner()),
            }
        })
    }
}

fn is_timeout(status: &tonic::Status) -> bool {
    if status.code() == tonic::Code::DeadlineExceeded {
        return true;
    }
    let mut source = status.source();
    while let Some(error) = source {
        if error.is::<tonic::TimeoutExpired>() {
            return true;
        }
        source = error.source();
    }
    false
}

fn encode_request(r: AuthorizationRequest) -> auth::CheckRequest {
    let source = r.remote.map(|a| auth::attribute_context::Peer {
        address: Some(core::Address {
            address: Some(core::address::Address::SocketAddress(core::SocketAddress {
                address: a.ip().to_string(),
                port_specifier: Some(core::socket_address::PortSpecifier::PortValue(
                    a.port() as u32
                )),
                ..Default::default()
            })),
        }),
        ..Default::default()
    });
    let time = r
        .time
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| prost_types::Timestamp {
            seconds: d.as_secs() as i64,
            nanos: d.subsec_nanos() as i32,
        });
    auth::CheckRequest {
        attributes: Some(auth::AttributeContext {
            source,
            request: Some(auth::attribute_context::Request {
                time,
                http: Some(auth::attribute_context::HttpRequest {
                    id: r.id,
                    method: r.method,
                    path: r.path,
                    host: r.authority,
                    scheme: r.scheme,
                    protocol: r.protocol,
                    header_map: Some(core::HeaderMap {
                        headers: r
                            .headers
                            .into_iter()
                            .filter(|(k, _)| k != "x-envoy-auth-partial-body")
                            .map(|(key, raw_value)| core::HeaderValue {
                                key,
                                raw_value,
                                ..Default::default()
                            })
                            .collect(),
                    }),
                    ..Default::default()
                }),
            }),
            context_extensions: r.context_extensions.into_iter().collect(),
            ..Default::default()
        }),
    }
}

#[allow(deprecated)]
fn mutations(
    headers: Vec<core::HeaderValueOption>,
    response: bool,
) -> Result<Vec<AuthorizationHeader>, AuthorizationError> {
    headers
        .into_iter()
        .map(|h| {
            let header = h.header.ok_or(AuthorizationError::InvalidMutation)?;
            if !header.raw_value.is_empty() {
                return Err(AuthorizationError::InvalidMutation);
            }
            let action = if let Some(append) = h.append {
                if append {
                    if response {
                        MutationAction::Add
                    } else {
                        MutationAction::Append
                    }
                } else {
                    MutationAction::Set
                }
            } else if !response {
                MutationAction::Set
            } else {
                match h.append_action {
                    0 => MutationAction::Add,
                    1 => MutationAction::AddIfAbsent,
                    2 => MutationAction::Set,
                    3 => MutationAction::OverwriteIfPresent,
                    _ => return Err(AuthorizationError::InvalidMutation),
                }
            };
            if h.keep_empty_value {
                return Err(AuthorizationError::Protocol);
            }
            // `raw_value` was rejected above, so `value` is the only source.
            Ok(AuthorizationHeader {
                name: header.key.to_ascii_lowercase(),
                value: header.value.into_bytes(),
                action,
            })
        })
        .collect()
}

#[allow(deprecated)]
fn decode_response(r: auth::CheckResponse) -> AuthorizationResult {
    use auth::check_response::HttpResponse;
    let ignored_metadata = r
        .dynamic_metadata
        .as_ref()
        .is_some_and(|m| !m.fields.is_empty())
        || matches!(&r.http_response, Some(HttpResponse::OkResponse(o)) if o.dynamic_metadata.as_ref().is_some_and(|m| !m.fields.is_empty()));
    let decision = (|| -> Result<AuthorizationDecision, AuthorizationError> {
        let status = r.status.map_or(0, |status| status.code);
        match (status, r.http_response) {
            (0, None) => Ok(AuthorizationDecision::Allow(AuthorizationAllow::default())),
            (0, Some(HttpResponse::OkResponse(o))) => {
                if !o.query_parameters_to_set.is_empty() || !o.query_parameters_to_remove.is_empty()
                {
                    return Err(AuthorizationError::Protocol);
                }
                Ok(AuthorizationDecision::Allow(AuthorizationAllow {
                    headers: mutations(o.headers, false)?,
                    remove: o.headers_to_remove,
                    response_headers: mutations(o.response_headers_to_add, true)?,
                }))
            }
            (_, Some(HttpResponse::ErrorResponse(_))) => Err(AuthorizationError::Protocol),
            (s, response) if s != 0 => {
                let denied = match response {
                    Some(HttpResponse::DeniedResponse(d)) => d,
                    None => auth::DeniedHttpResponse::default(),
                    _ => return Err(AuthorizationError::Protocol),
                };
                let status = denied
                    .status
                    .map(|s| s.code)
                    .filter(|s| *s != 0)
                    .unwrap_or(403);
                if !(200..=511).contains(&status) {
                    return Err(AuthorizationError::Protocol);
                }
                Ok(AuthorizationDecision::Denied(AuthorizationDenied {
                    status: status as u16,
                    body: denied.body.into_bytes(),
                    headers: mutations(denied.headers, false)?,
                }))
            }
            _ => Err(AuthorizationError::Protocol),
        }
    })()
    .unwrap_or_else(AuthorizationDecision::Error);
    AuthorizationResult {
        decision,
        ignored_metadata,
    }
}

#[cfg(any(test, feature = "test-support"))]
pub mod test_service {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };
    use tokio::{net::TcpListener, sync::Notify, task::JoinHandle};

    #[derive(Clone, Copy)]
    pub enum Mode {
        Allow,
        Mutate,
        /// Rewrites `:authority` (and adds `x-authorized`).
        MutateAuthority,
        InvalidMutation,
        Deny,
        TransportError,
        NoStatus,
        UnsupportedResponse,
        Stall,
    }
    pub struct TestService {
        pub address: SocketAddr,
        pub calls: Arc<AtomicUsize>,
        pub entered: Arc<Notify>,
        pub release: Arc<Notify>,
        /// Stalled handlers dropped before `release` (the client cancelled the RPC).
        pub cancelled: Arc<AtomicUsize>,
        pub(super) requests: Arc<Mutex<Vec<auth::CheckRequest>>>,
        task: JoinHandle<()>,
    }
    impl Drop for TestService {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    #[derive(Clone)]
    struct Service {
        mode: Mode,
        calls: Arc<AtomicUsize>,
        entered: Arc<Notify>,
        release: Arc<Notify>,
        cancelled: Arc<AtomicUsize>,
        requests: Arc<Mutex<Vec<auth::CheckRequest>>>,
    }
    /// Counts a handler future dropped mid-stall.
    // Rust note: dropping a future runs the destructors of its live locals, so a
    // guard held across an `.await` observes cancellation.
    struct CancelGuard(Arc<AtomicUsize>, bool);
    impl Drop for CancelGuard {
        fn drop(&mut self) {
            if !self.1 {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
    #[tonic::async_trait]
    impl auth::authorization_server::Authorization for Service {
        async fn check(
            &self,
            request: tonic::Request<auth::CheckRequest>,
        ) -> Result<tonic::Response<auth::CheckResponse>, tonic::Status> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.requests.lock().unwrap().push(request.into_inner());
            self.entered.notify_one();
            let status = |code| {
                Some(proxy_api::google::rpc::Status {
                    code,
                    ..Default::default()
                })
            };
            let response = match self.mode {
                Mode::Allow => auth::CheckResponse {
                    status: status(0),
                    http_response: Some(auth::check_response::HttpResponse::OkResponse(
                        auth::OkHttpResponse {
                            headers: vec![core::HeaderValueOption {
                                header: Some(core::HeaderValue {
                                    key: "x-authorized".into(),
                                    value: "yes".into(),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            }],
                            ..Default::default()
                        },
                    )),
                    ..Default::default()
                },
                Mode::Mutate | Mode::MutateAuthority | Mode::InvalidMutation => {
                    let header = |name: &str, value: &str| core::HeaderValueOption {
                        header: Some(core::HeaderValue {
                            key: name.into(),
                            value: value.into(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    };
                    let headers = if matches!(self.mode, Mode::InvalidMutation) {
                        vec![
                            header("x-authorized", "yes"),
                            header("x-invalid", "bad\nvalue"),
                        ]
                    } else if matches!(self.mode, Mode::MutateAuthority) {
                        vec![
                            header(":authority", "b.example"),
                            header("x-authorized", "yes"),
                        ]
                    } else {
                        vec![
                            header(":path", "/rerouted?q=2"),
                            header("x-authorized", "yes"),
                        ]
                    };
                    auth::CheckResponse {
                        status: status(0),
                        http_response: Some(auth::check_response::HttpResponse::OkResponse(
                            auth::OkHttpResponse {
                                headers,
                                headers_to_remove: vec!["x-remove".into()],
                                response_headers_to_add: vec![header("x-response", "authorized")],
                                ..Default::default()
                            },
                        )),
                        ..Default::default()
                    }
                }
                Mode::Deny => auth::CheckResponse {
                    status: status(7),
                    http_response: Some(auth::check_response::HttpResponse::DeniedResponse(
                        auth::DeniedHttpResponse {
                            status: Some(proxy_api::envoy::r#type::v3::HttpStatus { code: 401 }),
                            body: "denied".into(),
                            headers: vec![core::HeaderValueOption {
                                header: Some(core::HeaderValue {
                                    key: "x-denial".into(),
                                    value: "yes".into(),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            }],
                        },
                    )),
                    ..Default::default()
                },
                Mode::TransportError => return Err(tonic::Status::unavailable("injected fault")),
                Mode::NoStatus => auth::CheckResponse::default(),
                Mode::UnsupportedResponse => auth::CheckResponse {
                    status: status(0),
                    http_response: Some(auth::check_response::HttpResponse::OkResponse(
                        auth::OkHttpResponse {
                            query_parameters_to_set: vec![core::QueryParameter {
                                key: "unsupported".into(),
                                value: "operation".into(),
                            }],
                            ..Default::default()
                        },
                    )),
                    ..Default::default()
                },
                Mode::Stall => {
                    let mut guard = CancelGuard(self.cancelled.clone(), false);
                    self.release.notified().await;
                    guard.1 = true;
                    auth::CheckResponse {
                        status: status(0),
                        ..Default::default()
                    }
                }
            };
            Ok(tonic::Response::new(response))
        }
    }
    impl TestService {
        pub fn captured_requests(&self) -> Vec<AuthorizationRequest> {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .map(|request| {
                    let attributes = request.attributes.as_ref().unwrap();
                    let http = attributes.request.as_ref().unwrap().http.as_ref().unwrap();
                    AuthorizationRequest {
                        id: http.id.clone(),
                        method: http.method.clone(),
                        path: http.path.clone(),
                        authority: http.host.clone(),
                        scheme: http.scheme.clone(),
                        protocol: http.protocol.clone(),
                        headers: http
                            .header_map
                            .as_ref()
                            .map(|m| {
                                m.headers
                                    .iter()
                                    .map(|h| (h.key.clone(), h.raw_value.clone()))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        context_extensions: attributes
                            .context_extensions
                            .clone()
                            .into_iter()
                            .collect(),
                        ..Default::default()
                    }
                })
                .collect()
        }
        pub async fn spawn(mode: Mode) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let entered = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            let cancelled = Arc::new(AtomicUsize::new(0));
            let requests = Arc::new(Mutex::new(Vec::new()));
            let service = Service {
                mode,
                calls: calls.clone(),
                entered: entered.clone(),
                release: release.clone(),
                cancelled: cancelled.clone(),
                requests: requests.clone(),
            };
            let incoming = futures::stream::unfold(listener, |listener| async move {
                let result = listener.accept().await.map(|(s, _)| s);
                Some((result, listener))
            });
            let task = tokio::spawn(async move {
                tonic::transport::Server::builder()
                    .add_service(auth::authorization_server::AuthorizationServer::new(
                        service,
                    ))
                    .serve_with_incoming(incoming)
                    .await
                    .unwrap();
            });
            Self {
                address,
                calls,
                entered,
                release,
                cancelled,
                requests,
                task,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_service::{Mode, TestService};
    #[tokio::test(flavor = "multi_thread")]
    async fn grpc_v3_real_service_populates_raw_duplicate_headers_without_body() {
        let service = TestService::spawn(Mode::Allow).await;
        let client = GrpcAuthorizationClient::new(
            service.address,
            Duration::from_secs(2),
            Duration::from_secs(1),
        );
        let request = AuthorizationRequest {
            method: "POST".into(),
            path: "/v1?q=a%20b".into(),
            authority: "test".into(),
            scheme: "http".into(),
            headers: vec![
                ("x-repeat".into(), b"one".to_vec()),
                ("x-repeat".into(), vec![0x80]),
                ("x-envoy-auth-partial-body".into(), b"true".to_vec()),
            ],
            remote: Some("127.0.0.1:12345".parse().unwrap()),
            ..Default::default()
        };
        assert!(matches!(
            client.check(request).await.decision,
            AuthorizationDecision::Allow(_)
        ));
        let log = service.requests.lock().unwrap();
        let attributes = log[0].attributes.as_ref().unwrap();
        let http = attributes.request.as_ref().unwrap().http.as_ref().unwrap();
        assert_eq!(http.path, "/v1?q=a%20b");
        assert!(http.query.is_empty());
        assert!(http.body.is_empty() && http.raw_body.is_empty() && http.headers.is_empty());
        let headers = &http.header_map.as_ref().unwrap().headers;
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[1].raw_value, vec![0x80]);
        assert!(attributes.source.as_ref().unwrap().principal.is_empty());
        assert!(attributes.metadata_context.is_none() && attributes.tls_session.is_none());
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn grpc_v3_deadline_and_saturation_are_bounded_and_drop_releases_capacity() {
        let service = TestService::spawn(Mode::Stall).await;
        let warm = GrpcAuthorizationClient::new(
            service.address,
            Duration::from_secs(10),
            Duration::from_secs(10),
        );
        // Shares `warm`'s connection, so the deadline below is spent stalled in
        // the service rather than connecting to it.
        let client = GrpcAuthorizationClient {
            channel: warm.channel.clone(),
            permits: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
            timeout: Duration::from_millis(500),
        };
        let warming = tokio::spawn(warm.check(AuthorizationRequest::default()));
        tokio::time::timeout(Duration::from_secs(5), service.entered.notified())
            .await
            .unwrap();
        service.release.notify_one();
        let warmed = tokio::time::timeout(Duration::from_secs(5), warming)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(warmed.decision, AuthorizationDecision::Allow(_)));
        let pending: Vec<_> = (0..MAX_IN_FLIGHT)
            .map(|_| client.check(AuthorizationRequest::default()))
            .collect();
        assert!(matches!(
            client.check(AuthorizationRequest::default()).await.decision,
            AuthorizationDecision::Error(AuthorizationError::Saturation)
        ));
        drop(pending);
        let decision = client.check(AuthorizationRequest::default()).await.decision;
        assert!(
            matches!(
                decision,
                AuthorizationDecision::Error(AuthorizationError::Timeout)
            ),
            "{decision:?}"
        );
        // The dropped checks never sent an RPC; this one reached the stall.
        assert_eq!(service.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        let next = client.check(AuthorizationRequest::default());
        drop(next);
        let next = (0..MAX_IN_FLIGHT)
            .map(|_| client.check(AuthorizationRequest::default()))
            .collect::<Vec<_>>();
        assert!(matches!(
            client.check(AuthorizationRequest::default()).await.decision,
            AuthorizationDecision::Error(AuthorizationError::Saturation)
        ));
        drop(next);
    }
}
