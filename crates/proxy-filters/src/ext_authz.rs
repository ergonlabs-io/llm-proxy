//! Header-only external authorization. No principal is imported from a decision.
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use proxy_config::{authorization::*, ConfigError};
use proxy_http::filter::*;
use proxy_observability::{
    stats::{Handle, Instrument, InstrumentKind, Registry, WorkerId},
    ResponseFlag,
};
use std::{
    any::Any,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

static OUTCOMES: Instrument = Instrument {
    name: "ext_authz",
    kind: InstrumentKind::Counter,
    unit: "{request}",
    attribute_keys: &["scope", "outcome"],
    buckets: None,
};
const OUTCOME_NAMES: [&str; 7] = [
    "ok",
    "denied",
    "error",
    "invalid",
    "disabled",
    "failure_mode_allowed",
    "ignored_dynamic_metadata",
];

pub struct ExtAuthzStats {
    registry: Arc<Registry>,
    handles: [Handle; 7],
    fail_open_warned: AtomicBool,
}
impl ExtAuthzStats {
    pub fn new(registry: Arc<Registry>, scope: &str) -> Self {
        let handles = OUTCOME_NAMES.map(|outcome| {
            registry.resolve_capped(
                &OUTCOMES,
                &[("scope", scope), ("outcome", outcome)],
                1024,
                &[("scope", "overflow"), ("outcome", outcome)],
            )
        });
        Self {
            registry,
            handles,
            fail_open_warned: AtomicBool::new(false),
        }
    }
    fn record(&self, index: usize) {
        self.registry.incr(WorkerId(0), self.handles[index], 1);
    }
}

#[derive(Clone)]
pub struct ExtAuthzRoute(pub ExtAuthzPerRoute);
impl PerRouteConfig for ExtAuthzRoute {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn merge_from(&self, less: &dyn PerRouteConfig) -> Option<Arc<dyn PerRouteConfig>> {
        let less = less.as_any().downcast_ref::<Self>()?;
        let mut result = self.clone();
        if let ExtAuthzPerRoute::Check {
            context_extensions: more,
        } = &mut result.0
        {
            if let ExtAuthzPerRoute::Check {
                context_extensions: parent,
            } = &less.0
            {
                let mut merged = parent.clone();
                merged.extend(more.clone());
                *more = merged;
            }
        }
        Some(Arc::new(result))
    }
}

pub struct ExtAuthzFactory;
impl HttpFilterFactory for ExtAuthzFactory {
    fn type_url(&self) -> &'static str {
        TYPE_URL
    }
    fn may_buffer_response(&self) -> bool {
        false
    }
    fn create(
        &self,
        _: &prost_reflect::DynamicMessage,
        _: &FactoryContext,
    ) -> Result<Box<dyn FilterInstanceFactory>, ConfigError> {
        Err(ConfigError::InvalidValue {
            field_path: "typed_config".into(),
            reason: "ext_authz requires typed IR".into(),
        })
    }
    fn parse_ext_authz_per_route(
        &self,
        config: &ExtAuthzPerRoute,
    ) -> Result<Arc<dyn PerRouteConfig>, ConfigError> {
        Ok(Arc::new(ExtAuthzRoute(config.clone())))
    }
}

pub struct ExtAuthzInstanceFactory {
    pub config: ExtAuthzConfig,
    pub client: Arc<dyn AuthorizationClient>,
    pub stats: Arc<ExtAuthzStats>,
}
impl FilterInstanceFactory for ExtAuthzInstanceFactory {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(ExtAuthzFilter {
            config: self.config.clone(),
            client: self.client.clone(),
            stats: self.stats.clone(),
            pending: None,
            ready: None,
            applied: false,
            response_headers: Vec::new(),
        })
    }
}

struct ExtAuthzFilter {
    config: ExtAuthzConfig,
    client: Arc<dyn AuthorizationClient>,
    stats: Arc<ExtAuthzStats>,
    pending: Option<AuthorizationFuture>,
    ready: Option<AuthorizationResult>,
    applied: bool,
    response_headers: Vec<AuthorizationHeader>,
}

fn valid_headers(headers: &[AuthorizationHeader]) -> bool {
    headers.iter().all(|h| {
        (h.name.starts_with(':') || HeaderName::from_bytes(h.name.as_bytes()).is_ok())
            && HeaderValue::from_bytes(&h.value).is_ok()
    })
}
fn apply_regular(map: &mut HeaderMap, h: &AuthorizationHeader, request: bool) {
    let Ok(name) = HeaderName::from_bytes(h.name.as_bytes()) else {
        return;
    };
    let value = HeaderValue::from_bytes(&h.value).expect("validated mutation");
    match h.action {
        MutationAction::Set => {
            map.insert(name, value);
        }
        MutationAction::Add => {
            map.append(name, value);
        }
        MutationAction::OverwriteIfPresent => {
            if map.contains_key(&name) {
                map.insert(name, value);
            }
        }
        MutationAction::AddIfAbsent => {
            if !map.contains_key(&name) {
                map.insert(name, value);
            }
        }
        MutationAction::Append => {
            if request {
                if let Some(existing) = map.get(&name) {
                    let mut joined = existing.as_bytes().to_vec();
                    joined.push(b',');
                    joined.extend_from_slice(value.as_bytes());
                    map.insert(
                        name,
                        HeaderValue::from_bytes(&joined).expect("validated values"),
                    );
                }
            } else {
                map.append(name, value);
            }
        }
    }
}

impl ExtAuthzFilter {
    fn deny(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        denial: AuthorizationDenied,
        details: &'static str,
    ) {
        cb.stream_info()
            .set_response_flag(ResponseFlag::UnauthorizedExternalService);
        let headers = denial.headers;
        cb.send_local_reply_exact(
            StatusCode::from_u16(denial.status).expect("validated status"),
            std::str::from_utf8(&denial.body).expect("gRPC string body"),
            Some(Box::new(move |map| {
                for h in &headers {
                    apply_regular(map, h, false);
                }
            })),
            details,
        );
    }
    fn invalid(&mut self, cb: &mut dyn DecoderCallbacks) {
        self.stats.record(3);
        self.deny(
            cb,
            AuthorizationDenied {
                status: 500,
                body: Vec::new(),
                headers: Vec::new(),
            },
            "ext_authz_invalid",
        );
    }
    fn apply_allow(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        head: &mut RequestHeaders,
        allow: AuthorizationAllow,
    ) {
        let bytes: usize = allow
            .headers
            .iter()
            .chain(&allow.response_headers)
            .map(|h| h.name.len() + h.value.len())
            .sum::<usize>()
            + allow.remove.iter().map(String::len).sum::<usize>();
        if bytes > MAX_MUTATION_BYTES
            || !valid_headers(&allow.headers)
            || !valid_headers(&allow.response_headers)
            || allow
                .response_headers
                .iter()
                .any(|h| h.name.starts_with(':'))
        {
            self.invalid(cb);
            return;
        }
        // Validate into a copy so an invalid URI cannot leave partial mutations.
        let mut changed = head.clone();
        for h in &allow.headers {
            let result = match h.name.as_str() {
                ":method" => std::str::from_utf8(&h.value)
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .map(|v| changed.method = v),
                ":path" | ":authority" | "host" | ":scheme" => {
                    let mut parts = changed.uri.clone().into_parts();
                    let Ok(value) = std::str::from_utf8(&h.value) else {
                        self.invalid(cb);
                        return;
                    };
                    match h.name.as_str() {
                        ":path" => match value.parse() {
                            Ok(v) => parts.path_and_query = Some(v),
                            Err(_) => {
                                self.invalid(cb);
                                return;
                            }
                        },
                        ":scheme" => match value.parse() {
                            Ok(v) => parts.scheme = Some(v),
                            Err(_) => {
                                self.invalid(cb);
                                return;
                            }
                        },
                        _ => match value.parse() {
                            Ok(v) => {
                                parts.authority = Some(v);
                                if parts.scheme.is_none() {
                                    parts.scheme = Some(http::uri::Scheme::HTTP);
                                }
                            }
                            Err(_) => {
                                self.invalid(cb);
                                return;
                            }
                        },
                    }
                    match http::Uri::from_parts(parts) {
                        Ok(uri) => {
                            changed.uri = uri;
                            if h.name == "host" {
                                apply_regular(&mut changed.headers, h, true);
                            } else if h.name == ":authority" {
                                // Envoy treats `:authority` and `Host` as one header; the
                                // HTTP/1 upstream codec reads `Host`, so follow the same
                                // way the router's `host_rewrite_literal` does.
                                changed.headers.insert(
                                    http::header::HOST,
                                    HeaderValue::from_bytes(&h.value).expect("validated mutation"),
                                );
                            }
                            Some(())
                        }
                        Err(_) => None,
                    }
                }
                name if name.starts_with(':') => None,
                _ => {
                    apply_regular(&mut changed.headers, h, true);
                    Some(())
                }
            };
            if result.is_none() {
                self.invalid(cb);
                return;
            }
        }
        for name in &allow.remove {
            if !name.starts_with(':') && name != "host" {
                if let Ok(name) = HeaderName::from_bytes(name.as_bytes()) {
                    changed.headers.remove(name);
                }
            }
        }
        if changed
            .headers
            .iter()
            .map(|(k, v)| k.as_str().len() + v.as_bytes().len())
            .sum::<usize>()
            > MAX_MESSAGE_BYTES
        {
            self.invalid(cb);
            return;
        }
        if self.config.clear_route_cache && (!allow.headers.is_empty() || !allow.remove.is_empty())
        {
            cb.clear_route_cache();
        }
        *head = changed;
        self.response_headers = allow.response_headers;
        self.stats.record(0);
    }
}

impl HttpFilter for ExtAuthzFilter {
    fn decode_before_body(&self) -> bool {
        true
    }
    fn decode_headers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        head: &mut RequestHeaders,
        _: bool,
    ) -> FilterHeadersStatus {
        if self.applied {
            return FilterHeadersStatus::Continue;
        }
        if let Some(result) = self.ready.take() {
            self.applied = true;
            if result.ignored_metadata {
                self.stats.record(6);
            }
            match result.decision {
                AuthorizationDecision::Allow(allow) => self.apply_allow(cb, head, allow),
                AuthorizationDecision::Denied(d) => {
                    if d.headers
                        .iter()
                        .map(|h| h.name.len() + h.value.len())
                        .sum::<usize>()
                        > MAX_MUTATION_BYTES
                        || !(200..=511).contains(&d.status)
                        || std::str::from_utf8(&d.body).is_err()
                        || !valid_headers(&d.headers)
                        || d.headers.iter().any(|h| h.name.starts_with(':'))
                    {
                        self.invalid(cb);
                    } else {
                        self.stats.record(1);
                        self.deny(cb, d, "ext_authz_denied");
                    }
                }
                AuthorizationDecision::Error(AuthorizationError::InvalidMutation) => {
                    self.invalid(cb)
                }
                AuthorizationDecision::Error(AuthorizationError::RequestTooLarge) => {
                    // The client sized this request, so it is not an outage: always
                    // deny (431, as Envoy's codec does for oversized headers), never
                    // take the fail-open path, whatever `failure_mode_allow` says.
                    self.stats.record(2);
                    self.deny(
                        cb,
                        AuthorizationDenied {
                            status: StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE.as_u16(),
                            body: Vec::new(),
                            headers: Vec::new(),
                        },
                        "ext_authz_request_too_large",
                    );
                }
                AuthorizationDecision::Error(_) => {
                    self.stats.record(2);
                    if self.config.failure_mode_allow {
                        self.stats.record(5);
                        // AGENTS.md "Fail-open controls": warn on the bypass path only.
                        if !self.stats.fail_open_warned.swap(true, Ordering::Relaxed) {
                            tracing::warn!(cluster = %self.config.cluster, "external authorization failed; explicit failure_mode_allow admitted the request; repeats suppressed");
                        }
                        if self.config.failure_mode_allow_header_add {
                            head.headers.append(
                                "x-envoy-auth-failure-mode-allowed",
                                HeaderValue::from_static("true"),
                            );
                        }
                    } else {
                        self.deny(
                            cb,
                            AuthorizationDenied {
                                status: self.config.status_on_error,
                                body: Vec::new(),
                                headers: Vec::new(),
                            },
                            "ext_authz_error",
                        );
                    }
                }
            }
            return FilterHeadersStatus::Continue;
        }
        if self.pending.is_none() {
            let mut context_extensions = Default::default();
            if let Some(config) = cb.per_route_config() {
                if let Some(route) = config.as_any().downcast_ref::<ExtAuthzRoute>() {
                    match &route.0 {
                        ExtAuthzPerRoute::Disabled => {
                            self.applied = true;
                            self.stats.record(4);
                            return FilterHeadersStatus::Continue;
                        }
                        ExtAuthzPerRoute::Check {
                            context_extensions: context,
                        } => context_extensions = context.clone(),
                    }
                }
            }
            if context_extensions.len() > 64
                || context_extensions
                    .iter()
                    .map(|(k, v)| k.len() + v.len())
                    .sum::<usize>()
                    > MAX_MUTATION_BYTES
            {
                self.applied = true;
                self.invalid(cb);
                return FilterHeadersStatus::Continue;
            }
            let downstream = cb.stream_info().downstream;
            let authority = head
                .uri
                .authority()
                .map(|a| a.as_str())
                .or_else(|| head.headers.get("host").and_then(|v| v.to_str().ok()))
                .unwrap_or("")
                .to_owned();
            let scheme = head
                .uri
                .scheme_str()
                .unwrap_or(if downstream.is_some_and(|d| d.is_tls) {
                    "https"
                } else {
                    "http"
                })
                .to_owned();
            let path = head
                .uri
                .path_and_query()
                .map(|p| p.as_str())
                .unwrap_or("/")
                .to_owned();
            let mut headers = vec![
                (":method".into(), head.method.as_str().as_bytes().to_vec()),
                (":path".into(), path.as_bytes().to_vec()),
                (":authority".into(), authority.as_bytes().to_vec()),
                (":scheme".into(), scheme.as_bytes().to_vec()),
            ];
            headers.extend(
                head.headers
                    .iter()
                    .filter(|(k, _)| k.as_str() != "host")
                    .map(|(k, v)| (k.as_str().to_owned(), v.as_bytes().to_vec())),
            );
            self.pending = Some(self.client.check(AuthorizationRequest {
                method: head.method.to_string(),
                path,
                authority,
                scheme,
                headers,
                remote: downstream.map(|d| d.remote),
                context_extensions,
                time: Some(std::time::SystemTime::now()),
                ..Default::default()
            }));
        }
        FilterHeadersStatus::StopAllIterationAndWatermark
    }
    fn poll_pending<'a>(
        &'a mut self,
    ) -> Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>>> {
        let future = self.pending.take()?;
        Some(Box::pin(async move {
            self.ready = Some(future.await);
        }))
    }
    fn encode_headers(
        &mut self,
        _: &mut dyn EncoderCallbacks,
        head: &mut ResponseHeaders,
        _: bool,
    ) -> FilterHeadersStatus {
        for h in &self.response_headers {
            apply_regular(&mut head.headers, h, false);
        }
        FilterHeadersStatus::Continue
    }
    fn on_destroy(&mut self) {
        self.pending = None;
        self.ready = None;
    }
}
