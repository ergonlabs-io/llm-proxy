//! `llmproxy.guardrail`: sends each request's buffered body to a check and
//! refuses the request when the check denies it.
//!
//! It reads the tenant from auth, the requested model from `body_rewrite`,
//! and the resolved model from `model_resolver`; config validation places it
//! after those and after `model_authz`, so only authorized requests are
//! disclosed to a check, and before `token_limit`, `spend_limit` and `usage`,
//! so a denied request is never counted or charged. A denied request is a
//! local reply: no provider is dialled, so it gets no ledger entry (ADR-0009).
//!
//! The filter only allows or denies; it never changes the request. Decode is
//! fully buffered, so `decode_data` sees the whole body once and the check
//! runs there, also for a trailered request. A request with an empty body has
//! no prompt to judge and is not checked.
//!
//! Each check has an explicit failure mode (AGENTS.md "Fail-open controls").
//! Fail closed refuses on an error, a timeout, or a body over the check's
//! limit. Fail open admits those requests, counts each one, and logs a
//! rate-limited warning naming the check's host. Neither the body, the
//! check's reason, nor any request header reaches a log line or a metric.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use prost_reflect::DynamicMessage;
use proxy_config::ConfigError;
use proxy_http::filter::{
    DecoderCallbacks, FactoryContext, FilterDataStatus, FilterHeadersStatus, FilterInstanceFactory,
    HttpFilter, HttpFilterFactory, RequestHeaders,
};
use proxy_observability::stats::{Handle, Instrument, InstrumentKind, Registry, WorkerId};

use crate::object_ownership::Warn;

/// Type URL this filter is registered under.
pub const TYPE_URL: &str = "type.llmproxy.dev/llmproxy.filters.v0.Guardrail";

/// `SharedFactoryState` key for this chain's counters and fail-open warner, so
/// every worker building the chain shares them.
const STATS_KEY: &str = "llmproxy.guardrail.stats";

/// The largest check response read. A longer answer is an error.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// The most bytes of a deny reason returned to the client.
const MAX_REASON_BYTES: usize = 256;

static CHECKS: Instrument = Instrument {
    name: "llmproxy_guardrail_checks_total",
    kind: InstrumentKind::Counter,
    unit: "{request}",
    attribute_keys: &["scope", "outcome"],
    buckets: None,
};

/// One outcome per request, except that a fail-open admission counts both its
/// cause and `failure_mode_allowed`. The names are also the
/// `%LLM_GUARDRAIL%` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Allowed,
    Denied,
    Error,
    Timeout,
    OverLimit,
    FailureModeAllowed,
}

impl Outcome {
    const ALL: [Outcome; 6] = [
        Outcome::Allowed,
        Outcome::Denied,
        Outcome::Error,
        Outcome::Timeout,
        Outcome::OverLimit,
        Outcome::FailureModeAllowed,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Outcome::Allowed => "allowed",
            Outcome::Denied => "denied",
            Outcome::Error => "error",
            Outcome::Timeout => "timeout",
            Outcome::OverLimit => "over_limit",
            Outcome::FailureModeAllowed => "failure_mode_allowed",
        }
    }
}

fn invalid(field_path: impl Into<String>, reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidValue {
        field_path: field_path.into(),
        reason: reason.into(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailureMode {
    Closed,
    Open,
}

/// A parsed `HttpGuardrail`.
struct HttpCheck {
    host: String,
    port: u16,
    /// `host:port` for the `host` header and for logs. Never the path or
    /// query, which may carry a token.
    authority: String,
    path_and_query: String,
    /// `Some` for `https`.
    tls: Option<tokio_rustls::TlsConnector>,
    timeout: Duration,
    max_body_bytes: u64,
}

struct Check {
    http: HttpCheck,
    failure_mode: FailureMode,
}

/// Parsed `typed_config`.
pub struct GuardrailConfig {
    default: Arc<Check>,
    tenants: HashMap<String, Arc<Check>>,
}

impl GuardrailConfig {
    fn check_for(&self, tenant: Option<&str>) -> &Arc<Check> {
        tenant
            .and_then(|tenant| self.tenants.get(tenant))
            .unwrap_or(&self.default)
    }
}

fn message_field(
    msg: &DynamicMessage,
    name: &str,
    path: &str,
) -> Result<Option<DynamicMessage>, ConfigError> {
    if !msg.has_field_by_name(name) {
        return Ok(None);
    }
    msg.get_field_by_name(name)
        .and_then(|v| v.as_message().cloned())
        .map(Some)
        .ok_or_else(|| invalid(path, "must be a message"))
}

/// Built at most once per config, and only when some check uses `https`:
/// loading the platform roots reads disk.
fn tls_connector() -> Result<tokio_rustls::TlsConnector, String> {
    let roots = crate::jwks_refresh::tls_roots(None)?;
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| format!("TLS setup: {e:?}"))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

fn parse_http(
    msg: &DynamicMessage,
    path: &str,
    tls: &mut Option<tokio_rustls::TlsConnector>,
) -> Result<HttpCheck, ConfigError> {
    let uri_path = format!("{path}.uri");
    let raw = msg
        .get_field_by_name("uri")
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    if raw.is_empty() {
        return Err(invalid(&uri_path, "must not be empty"));
    }
    let uri: http::Uri = raw
        .parse()
        .map_err(|e| invalid(&uri_path, format!("not a valid URI: {e}")))?;
    let https = match uri.scheme_str() {
        Some("http") => false,
        Some("https") => true,
        _ => {
            return Err(invalid(
                &uri_path,
                "must be an absolute `http` or `https` URI",
            ))
        }
    };
    let authority = uri
        .authority()
        .ok_or_else(|| invalid(&uri_path, "must name a host"))?;
    // A credential in the URI would be logged with the authority.
    if authority.as_str().contains('@') {
        return Err(invalid(&uri_path, "must not carry user information"));
    }
    let host = uri.host().unwrap_or_default();
    if host.is_empty() {
        return Err(invalid(&uri_path, "must name a host"));
    }
    let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let tls = if https {
        if tls.is_none() {
            *tls = Some(tls_connector().map_err(|e| invalid(&uri_path, e))?);
        }
        if rustls::pki_types::ServerName::try_from(host.clone()).is_err() {
            return Err(invalid(
                &uri_path,
                "the host is not a valid TLS server name",
            ));
        }
        tls.clone()
    } else {
        None
    };

    let timeout_ms = msg
        .get_field_by_name("timeout_ms")
        .and_then(|v| v.as_u32())
        .unwrap_or(0);
    if timeout_ms == 0 {
        return Err(invalid(
            format!("{path}.timeout_ms"),
            "must be greater than 0; a check must be bounded",
        ));
    }
    let max_body_bytes = msg
        .get_field_by_name("max_body_bytes")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if max_body_bytes == 0 {
        return Err(invalid(
            format!("{path}.max_body_bytes"),
            "must be greater than 0",
        ));
    }
    Ok(HttpCheck {
        authority: format!("{}:{port}", uri.host().unwrap_or_default()),
        host,
        port,
        path_and_query: uri
            .path_and_query()
            .map_or_else(|| "/".to_string(), |pq| pq.as_str().to_string()),
        tls,
        timeout: Duration::from_millis(u64::from(timeout_ms)),
        max_body_bytes,
    })
}

fn parse_check(
    msg: &DynamicMessage,
    path: &str,
    tls: &mut Option<tokio_rustls::TlsConnector>,
) -> Result<Check, ConfigError> {
    let Some(http) = message_field(msg, "http", &format!("{path}.http"))? else {
        return Err(invalid(
            path,
            "a backend is required; `http` is the only backend supported",
        ));
    };
    let http = parse_http(&http, &format!("{path}.http"), tls)?;
    let failure_mode = match msg
        .get_field_by_name("failure_mode")
        .and_then(|v| v.as_enum_number())
        .unwrap_or(0)
    {
        1 => FailureMode::Closed,
        2 => FailureMode::Open,
        0 => {
            return Err(invalid(
                format!("{path}.failure_mode"),
                "must be set to FAIL_CLOSED or FAIL_OPEN; there is no default",
            ))
        }
        other => {
            return Err(invalid(
                format!("{path}.failure_mode"),
                format!("unknown value {other}; expected FAIL_CLOSED or FAIL_OPEN"),
            ))
        }
    };
    Ok(Check { http, failure_mode })
}

/// Parses `typed_config`. Every field maps to the parsed config or fails with
/// its dotted path (AGENTS.md invariant 1).
pub fn parse_config(config: &DynamicMessage) -> Result<GuardrailConfig, ConfigError> {
    let mut tls = None;
    let Some(default) = message_field(config, "default_check", "typed_config.default_check")?
    else {
        return Err(invalid(
            "typed_config.default_check",
            "is required; a request with no tenant rule must still be checked",
        ));
    };
    let default = Arc::new(parse_check(
        &default,
        "typed_config.default_check",
        &mut tls,
    )?);

    let entries = config
        .get_field_by_name("tenants")
        .and_then(|v| v.as_list().map(<[_]>::to_vec))
        .unwrap_or_default();
    let mut tenants = HashMap::with_capacity(entries.len());
    let mut seen: HashMap<String, usize> = HashMap::new();
    for (i, entry) in entries.iter().enumerate() {
        let path = format!("typed_config.tenants[{i}]");
        let msg = entry
            .as_message()
            .ok_or_else(|| invalid(&path, "must be a message"))?;
        let tenant = msg
            .get_field_by_name("tenant")
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        if tenant.is_empty() {
            return Err(invalid(format!("{path}.tenant"), "must not be empty"));
        }
        if let Some(&first) = seen.get(&tenant) {
            return Err(invalid(
                format!("{path}.tenant"),
                format!("duplicate `tenant`; already configured at index {first}"),
            ));
        }
        let Some(check) = message_field(msg, "check", &format!("{path}.check"))? else {
            return Err(invalid(format!("{path}.check"), "is required"));
        };
        let check = parse_check(&check, &format!("{path}.check"), &mut tls)?;
        seen.insert(tenant.clone(), i);
        tenants.insert(tenant, Arc::new(check));
    }
    Ok(GuardrailConfig { default, tenants })
}

/// Counters and the fail-open warner, shared by every worker building one
/// chain so a rebuild neither resets the counts nor re-logs the bypass.
struct GuardrailStats {
    exported: Option<(Arc<Registry>, [Handle; 6])>,
    fail_open: Warn,
}

impl GuardrailStats {
    fn new(registry: Option<Arc<Registry>>, scope: &str) -> Self {
        let exported = registry.map(|registry| {
            let handles = Outcome::ALL.map(|outcome| {
                registry.resolve_capped(
                    &CHECKS,
                    &[("scope", scope), ("outcome", outcome.as_str())],
                    1024,
                    &[("scope", "overflow"), ("outcome", outcome.as_str())],
                )
            });
            (registry, handles)
        });
        Self {
            exported,
            fail_open: Warn::default(),
        }
    }

    fn record(&self, outcome: Outcome) {
        if let Some((registry, handles)) = &self.exported {
            let index = Outcome::ALL
                .iter()
                .position(|o| *o == outcome)
                .expect("ALL lists every outcome");
            registry.incr(WorkerId(0), handles[index], 1);
        }
    }
}

#[derive(Default)]
pub struct GuardrailFilterFactory;

impl HttpFilterFactory for GuardrailFilterFactory {
    fn type_url(&self) -> &'static str {
        TYPE_URL
    }

    fn may_buffer_response(&self) -> bool {
        false
    }

    fn create(
        &self,
        config: &DynamicMessage,
        ctx: &FactoryContext,
    ) -> Result<Box<dyn FilterInstanceFactory>, ConfigError> {
        let config = Arc::new(parse_config(config)?);
        // Looked up before `get_or_try_init`: its closure runs under the
        // singleton map's lock, which `get` also takes.
        let registry = ctx
            .shared
            .get("", crate::usage_filter::STATS_REGISTRY_KEY)
            .and_then(|any| any.downcast::<Registry>().ok());
        let stats = ctx
            .get_or_try_init(STATS_KEY, || {
                Ok(Arc::new(GuardrailStats::new(registry, &ctx.stat_prefix))
                    as Arc<dyn std::any::Any + Send + Sync>)
            })?
            .downcast::<GuardrailStats>()
            .expect("the guardrail stats singleton is always GuardrailStats");
        Ok(Box::new(GuardrailInstanceFactory { config, stats }))
    }
}

struct GuardrailInstanceFactory {
    config: Arc<GuardrailConfig>,
    stats: Arc<GuardrailStats>,
}

impl FilterInstanceFactory for GuardrailInstanceFactory {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(GuardrailFilterInstance {
            config: Arc::clone(&self.config),
            stats: Arc::clone(&self.stats),
            pending: None,
            ready: None,
            decided: false,
        })
    }
}

/// What one check answered.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Allow,
    /// The reason, already bounded for the client reply.
    Deny(Option<String>),
    Error,
    Timeout,
    OverLimit,
}

/// The check, carrying everything it needs: per `poll_pending`'s contract the
/// future borrows nothing from the callbacks.
type CheckFuture = Pin<Box<dyn Future<Output = (Arc<Check>, Verdict)>>>;

struct GuardrailFilterInstance {
    config: Arc<GuardrailConfig>,
    stats: Arc<GuardrailStats>,
    pending: Option<CheckFuture>,
    ready: Option<(Arc<Check>, Verdict)>,
    decided: bool,
}

/// The JSON document a check receives. A body that is not UTF-8 goes as
/// `body_base64` so the check sees exactly the bytes the provider would.
fn check_payload(
    tenant: Option<&str>,
    requested_model: Option<&str>,
    resolved_model: Option<&str>,
    body: &[u8],
) -> Vec<u8> {
    let mut doc = serde_json::json!({
        "tenant": tenant,
        "requested_model": requested_model,
        "resolved_model": resolved_model,
    });
    match std::str::from_utf8(body) {
        Ok(text) => doc["body"] = serde_json::Value::String(text.to_string()),
        Err(_) => {
            doc["body_base64"] =
                serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(body))
        }
    }
    serde_json::to_vec(&doc).expect("a JSON value always serializes")
}

/// Bounds a deny reason for the client reply: control characters dropped,
/// at most [`MAX_REASON_BYTES`], cut on a character boundary.
fn bounded_reason(reason: &str) -> Option<String> {
    let mut out = String::new();
    for c in reason.chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > MAX_REASON_BYTES {
            break;
        }
        out.push(c);
    }
    let out = out.trim().to_string();
    (!out.is_empty()).then_some(out)
}

#[derive(serde::Deserialize)]
struct Answer {
    decision: String,
    #[serde(default)]
    reason: Option<String>,
}

fn parse_answer(body: &[u8]) -> Verdict {
    match serde_json::from_slice::<Answer>(body) {
        Ok(answer) if answer.decision == "allow" => Verdict::Allow,
        Ok(answer) if answer.decision == "deny" => {
            Verdict::Deny(answer.reason.as_deref().and_then(bounded_reason))
        }
        _ => Verdict::Error,
    }
}

async fn send<IO>(io: IO, check: &HttpCheck, payload: Vec<u8>) -> Result<Vec<u8>, ()>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(io))
            .await
            .map_err(drop)?;
    // Rust note: the connection task ends once `sender` is dropped, which
    // happens when this future completes or the timeout drops it.
    tokio::task::spawn(async move {
        let _ = conn.await;
    });
    let req = hyper::Request::post(check.path_and_query.as_str())
        .header(http::header::HOST, check.authority.as_str())
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::USER_AGENT, "llm-proxy")
        .body(Full::new(Bytes::from(payload)))
        .map_err(drop)?;
    let res = sender.send_request(req).await.map_err(drop)?;
    if res.status() != StatusCode::OK {
        return Err(());
    }
    let body = Limited::new(res.into_body(), MAX_RESPONSE_BYTES)
        .collect()
        .await
        .map_err(drop)?
        .to_bytes();
    Ok(body.to_vec())
}

async fn run_http_check(check: &HttpCheck, payload: Vec<u8>) -> Verdict {
    let work = async {
        let tcp = tokio::net::TcpStream::connect((check.host.as_str(), check.port))
            .await
            .map_err(drop)?;
        match &check.tls {
            None => send(tcp, check, payload).await,
            Some(connector) => {
                let name =
                    rustls::pki_types::ServerName::try_from(check.host.clone()).map_err(drop)?;
                let tls = connector.connect(name, tcp).await.map_err(drop)?;
                send(tls, check, payload).await
            }
        }
    };
    match tokio::time::timeout(check.timeout, work).await {
        Err(_) => Verdict::Timeout,
        Ok(Err(())) => Verdict::Error,
        Ok(Ok(body)) => parse_answer(&body),
    }
}

fn json_reply(message: &str, kind: &str) -> String {
    serde_json::json!({ "error": { "message": message, "type": kind } }).to_string()
}

fn json_content_type() -> proxy_http::filter::HeaderMutationFn {
    Box::new(|headers: &mut HeaderMap| {
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
    })
}

impl GuardrailFilterInstance {
    fn start(&mut self, cb: &mut dyn DecoderCallbacks, body: &Bytes) -> FilterDataStatus {
        // Rust note: clone out and drop the `RefMut` guard before any other
        // call on `cb`.
        let (tenant, requested, resolved) = {
            let info = cb.stream_info();
            (
                info.auth.tenant.clone(),
                info.requested_model.clone(),
                info.resolved_model.clone(),
            )
        };
        let check = Arc::clone(self.config.check_for(tenant.as_deref()));
        if body.len() as u64 > check.http.max_body_bytes {
            self.decided = true;
            self.apply(cb, &check, Verdict::OverLimit);
            return FilterDataStatus::Continue;
        }
        let payload = check_payload(
            tenant.as_deref(),
            requested.as_deref(),
            resolved.as_deref(),
            body,
        );
        self.pending = Some(Box::pin(async move {
            let verdict = run_http_check(&check.http, payload).await;
            (check, verdict)
        }));
        FilterDataStatus::StopIterationAndBuffer
    }

    fn apply(&mut self, cb: &mut dyn DecoderCallbacks, check: &Check, verdict: Verdict) {
        let cause = match verdict {
            Verdict::Allow => {
                self.finish(cb, Outcome::Allowed);
                return;
            }
            Verdict::Deny(reason) => {
                self.finish(cb, Outcome::Denied);
                let message = match reason {
                    Some(reason) => format!("request denied by guardrail: {reason}"),
                    None => "request denied by guardrail".to_string(),
                };
                cb.send_local_reply(
                    StatusCode::FORBIDDEN,
                    &json_reply(&message, "guardrail_denied"),
                    Some(json_content_type()),
                    "guardrail_denied",
                );
                return;
            }
            Verdict::Error => Outcome::Error,
            Verdict::Timeout => Outcome::Timeout,
            Verdict::OverLimit => Outcome::OverLimit,
        };
        self.stats.record(cause);
        match check.failure_mode {
            FailureMode::Open => {
                // AGENTS.md "Fail-open controls": the owner chose
                // availability, so the bypass is admitted and made visible.
                self.finish(cb, Outcome::FailureModeAllowed);
                self.stats.fail_open.emit(|suppressed| {
                    tracing::warn!(
                        check = %check.http.authority,
                        cause = cause.as_str(),
                        suppressed,
                        "llmproxy.guardrail: the check could not decide; FAIL_OPEN admitted the \
                         request unchecked; repeats are suppressed for a minute"
                    );
                });
            }
            FailureMode::Closed => {
                cb.stream_info().guardrail = Some(cause.as_str());
                let (status, message) = match cause {
                    Outcome::OverLimit => (
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "request body exceeds the guardrail limit",
                    ),
                    _ => (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "the guardrail check is unavailable",
                    ),
                };
                let details = match cause {
                    Outcome::OverLimit => "guardrail_over_limit",
                    Outcome::Timeout => "guardrail_timeout",
                    _ => "guardrail_error",
                };
                cb.send_local_reply(
                    status,
                    &json_reply(message, details),
                    Some(json_content_type()),
                    details,
                );
            }
        }
    }

    /// Records `outcome` on the counter and for `%LLM_GUARDRAIL%`.
    fn finish(&self, cb: &mut dyn DecoderCallbacks, outcome: Outcome) {
        self.stats.record(outcome);
        cb.stream_info().guardrail = Some(outcome.as_str());
    }
}

impl HttpFilter for GuardrailFilterInstance {
    fn decode_headers(
        &mut self,
        _cb: &mut dyn DecoderCallbacks,
        _headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        // An instance serves one stream in production; resetting here keeps
        // the latch honest if one is ever reused.
        self.decided = false;
        self.pending = None;
        self.ready = None;
        FilterHeadersStatus::Continue
    }

    /// Decode is fully buffered, so this sees the whole body exactly once
    /// (`end_stream` is false only when trailers follow), and again after
    /// [`Self::poll_pending`] resolves the check.
    fn decode_data(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        data: &mut Bytes,
        _end_stream: bool,
    ) -> FilterDataStatus {
        if self.decided {
            return FilterDataStatus::Continue;
        }
        if let Some((check, verdict)) = self.ready.take() {
            self.decided = true;
            self.apply(cb, &check, verdict);
            return FilterDataStatus::Continue;
        }
        if self.pending.is_some() {
            return FilterDataStatus::StopIterationAndBuffer;
        }
        if data.is_empty() {
            self.decided = true;
            return FilterDataStatus::Continue;
        }
        self.start(cb, data)
    }

    fn poll_pending<'a>(&'a mut self) -> Option<Pin<Box<dyn Future<Output = ()> + 'a>>> {
        let future = self.pending.take()?;
        Some(Box::pin(async move {
            self.ready = Some(future.await);
        }))
    }

    fn on_destroy(&mut self) {
        self.pending = None;
        self.ready = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::{RefCell, RefMut};
    use std::net::SocketAddr;

    use http::{Method, Uri};
    use proxy_config::ir::RouteEntry;
    use proxy_http::filter::{BufferedBody, HeaderMutationFn, PerRouteConfig};
    use proxy_http::stream_info::StreamInfo;
    use proxy_observability::stats::StatsControl;
    use serde_json::{json, Value};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    /// Bounds every check-driving test, so a hung check fails instead of
    /// stalling (AGENTS.md "Build And Test").
    const TEST_BOUND: Duration = Duration::from_secs(10);

    // --- config scaffolding ---------------------------------------------------

    fn parse_json(value: Value) -> Result<GuardrailConfig, ConfigError> {
        let desc = proxy_api::descriptor_pool()
            .get_message_by_name("llmproxy.filters.v0.Guardrail")
            .expect("Guardrail is compiled into proxy-api");
        let msg = DynamicMessage::deserialize(desc, value).expect("the JSON maps onto Guardrail");
        parse_config(&msg)
    }

    fn http_check(uri: &str, failure_mode: &str) -> Value {
        json!({
            "http": { "uri": uri, "timeout_ms": 2000, "max_body_bytes": 1024 },
            "failure_mode": failure_mode,
        })
    }

    fn field_path(err: ConfigError) -> String {
        match err {
            ConfigError::InvalidValue { field_path, .. } => field_path,
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    // --- config parsing -------------------------------------------------------

    #[test]
    fn each_invalid_config_names_its_field_path() {
        let ok = http_check("http://127.0.0.1:9/check", "FAIL_CLOSED");
        let cases = [
            (json!({}), "typed_config.default_check"),
            (
                json!({ "default_check": { "failure_mode": "FAIL_CLOSED" } }),
                "typed_config.default_check",
            ),
            (
                json!({ "default_check": { "http": ok["http"] } }),
                "typed_config.default_check.failure_mode",
            ),
            (
                json!({ "default_check": http_check("ftp://h/check", "FAIL_OPEN") }),
                "typed_config.default_check.http.uri",
            ),
            (
                json!({ "default_check": http_check("/relative", "FAIL_OPEN") }),
                "typed_config.default_check.http.uri",
            ),
            (
                json!({ "default_check": http_check("http://user:pw@h/check", "FAIL_OPEN") }),
                "typed_config.default_check.http.uri",
            ),
            (
                json!({ "default_check": {
                    "http": { "uri": "http://h/c", "max_body_bytes": 1 },
                    "failure_mode": "FAIL_OPEN" } }),
                "typed_config.default_check.http.timeout_ms",
            ),
            (
                json!({ "default_check": {
                    "http": { "uri": "http://h/c", "timeout_ms": 1 },
                    "failure_mode": "FAIL_OPEN" } }),
                "typed_config.default_check.http.max_body_bytes",
            ),
            (
                json!({ "default_check": ok, "tenants": [{ "tenant": "", "check": ok }] }),
                "typed_config.tenants[0].tenant",
            ),
            (
                json!({ "default_check": ok, "tenants": [{ "tenant": "acme" }] }),
                "typed_config.tenants[0].check",
            ),
            (
                json!({ "default_check": ok, "tenants": [
                    { "tenant": "acme", "check": ok },
                    { "tenant": "acme", "check": ok },
                ] }),
                "typed_config.tenants[1].tenant",
            ),
            (
                json!({ "default_check": ok, "tenants": [{ "tenant": "acme", "check": {
                    "http": ok["http"], "failure_mode": "FAILURE_MODE_UNSPECIFIED" } }] }),
                "typed_config.tenants[0].check.failure_mode",
            ),
        ];
        for (config, path) in cases {
            let err = parse_json(config.clone())
                .err()
                .unwrap_or_else(|| panic!("{config} must not load"));
            assert_eq!(field_path(err), path, "{config}");
        }
    }

    #[test]
    fn a_valid_config_parses_each_check() {
        let config = parse_json(json!({
            "default_check": http_check("http://127.0.0.1:9/check?v=1", "FAIL_CLOSED"),
            "tenants": [{ "tenant": "acme", "check": http_check("http://[::1]:7/acme", "FAIL_OPEN") }],
        }))
        .unwrap();
        assert_eq!(config.default.failure_mode, FailureMode::Closed);
        assert_eq!(config.default.http.path_and_query, "/check?v=1");
        assert_eq!(config.default.http.authority, "127.0.0.1:9");
        let acme = config.check_for(Some("acme"));
        assert_eq!(acme.failure_mode, FailureMode::Open);
        assert_eq!(acme.http.host, "::1");
        assert_eq!(acme.http.port, 7);
        assert!(Arc::ptr_eq(
            config.check_for(Some("globex")),
            &config.default
        ));
        assert!(Arc::ptr_eq(config.check_for(None), &config.default));
    }

    // --- payload and answer -----------------------------------------------------

    #[test]
    fn a_utf8_body_is_sent_as_text_and_any_other_as_base64() {
        let doc: Value = serde_json::from_slice(&check_payload(
            Some("acme"),
            Some("auto"),
            Some("fast"),
            b"hi",
        ))
        .unwrap();
        assert_eq!(
            doc,
            json!({ "tenant": "acme", "requested_model": "auto", "resolved_model": "fast", "body": "hi" })
        );
        let doc: Value =
            serde_json::from_slice(&check_payload(None, None, None, &[0xff, 0x00])).unwrap();
        assert_eq!(doc["body_base64"], "/wA=");
        assert!(doc.get("body").is_none());
        assert_eq!(doc["tenant"], Value::Null);
    }

    #[test]
    fn only_an_exact_allow_or_deny_is_a_decision() {
        assert_eq!(parse_answer(br#"{"decision":"allow"}"#), Verdict::Allow);
        assert_eq!(
            parse_answer(br#"{"decision":"deny","reason":"no secrets"}"#),
            Verdict::Deny(Some("no secrets".into()))
        );
        assert_eq!(parse_answer(br#"{"decision":"deny"}"#), Verdict::Deny(None));
        for body in [
            &br#"{"decision":"ALLOW"}"#[..],
            br#"{"allow":true}"#,
            b"allow",
            b"",
        ] {
            assert_eq!(parse_answer(body), Verdict::Error, "{body:?}");
        }
    }

    #[test]
    fn a_deny_reason_is_bounded_for_the_client() {
        assert_eq!(bounded_reason("a\u{0}b\nc"), Some("abc".into()));
        assert_eq!(bounded_reason(" \n "), None);
        let long = "é".repeat(MAX_REASON_BYTES);
        let bounded = bounded_reason(&long).unwrap();
        assert!(bounded.len() <= MAX_REASON_BYTES);
        assert_eq!(bounded.chars().count(), MAX_REASON_BYTES / 2);
    }

    // --- a real check service -------------------------------------------------

    /// How the mock check answers.
    #[derive(Clone)]
    enum Answering {
        /// 200 with `{"decision":"deny"}` when the payload's `body` contains
        /// the needle, otherwise allow.
        DenyWhenBodyContains(&'static str),
        Status(u16),
        /// Reads the request and never answers.
        Hang,
    }

    /// A check service. Every payload it receives is sent on the channel, so
    /// an empty channel proves the check was never asked.
    async fn spawn_check(answering: Answering) -> (SocketAddr, mpsc::UnboundedReceiver<Value>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let tx = tx.clone();
                let answering = answering.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let (head_end, length) = loop {
                        let Ok(n) = stream.read(&mut chunk).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&buf[..i]).to_ascii_lowercase();
                            let length = head
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length:"))
                                .and_then(|v| v.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            break (i + 4, length);
                        }
                    };
                    while buf.len() < head_end + length {
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let payload: Value =
                        serde_json::from_slice(&buf[head_end..head_end + length]).unwrap();
                    let body_text = payload["body"].as_str().unwrap_or_default().to_string();
                    let _ = tx.send(payload);
                    let (status, body) = match answering {
                        Answering::Hang => {
                            tokio::time::sleep(Duration::from_secs(3600)).await;
                            return;
                        }
                        Answering::Status(status) => (status, String::new()),
                        Answering::DenyWhenBodyContains(needle) if body_text.contains(needle) => (
                            200,
                            r#"{"decision":"deny","reason":"the prompt names a secret"}"#
                                .to_string(),
                        ),
                        Answering::DenyWhenBodyContains(_) => {
                            (200, r#"{"decision":"allow"}"#.to_string())
                        }
                    };
                    let _ = stream
                        .write_all(
                            format!(
                                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            )
                            .as_bytes(),
                        )
                        .await;
                });
            }
        });
        (addr, rx)
    }

    /// A port nothing listens on: bound, then released.
    async fn closed_port() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    }

    fn check_json(addr: SocketAddr, failure_mode: &str, timeout_ms: u32, max: u64) -> Value {
        json!({
            "http": {
                "uri": format!("http://{addr}/v1/check"),
                "timeout_ms": timeout_ms,
                "max_body_bytes": max,
            },
            "failure_mode": failure_mode,
        })
    }

    // --- request scaffolding --------------------------------------------------

    struct LocalReply {
        status: StatusCode,
        body: String,
        details: String,
    }

    struct TestCallbacks {
        stream_info: RefCell<StreamInfo>,
        local_reply: Option<LocalReply>,
    }

    impl TestCallbacks {
        fn new(tenant: Option<&str>, requested: Option<&str>, resolved: Option<&str>) -> Self {
            let mut info = StreamInfo::default();
            info.auth.tenant = tenant.map(str::to_owned);
            info.requested_model = requested.map(str::to_owned);
            info.resolved_model = resolved.map(str::to_owned);
            TestCallbacks {
                stream_info: RefCell::new(info),
                local_reply: None,
            }
        }

        fn outcome(&self) -> Option<&'static str> {
            self.stream_info.borrow().guardrail
        }
    }

    impl DecoderCallbacks for TestCallbacks {
        fn send_local_reply(
            &mut self,
            code: StatusCode,
            body: &str,
            _modify_headers: Option<HeaderMutationFn>,
            details: &str,
        ) {
            self.local_reply = Some(LocalReply {
                status: code,
                body: body.to_string(),
                details: details.to_string(),
            });
        }
        fn continue_decoding(&mut self) {
            unimplemented!("the guardrail resumes through poll_pending")
        }
        fn add_decoded_data(&mut self, _data: Bytes, _streaming: bool) {
            unimplemented!("the guardrail never adds request data")
        }
        fn inject_decoded_data_to_filter_chain(&mut self, _data: Bytes, _end_stream: bool) {
            unimplemented!("the guardrail never injects data")
        }
        fn decoding_buffer(&self) -> Option<&BufferedBody> {
            unimplemented!("the guardrail reads the body from decode_data")
        }
        fn modify_decoding_buffer(&mut self, _f: &mut dyn FnMut(&mut bytes::BytesMut)) {
            unimplemented!("the guardrail never changes request bytes")
        }
        fn route(&mut self) -> Option<Arc<RouteEntry>> {
            None
        }
        fn clear_route_cache(&mut self) {
            unimplemented!("the guardrail never changes routing")
        }
        fn per_route_config(&mut self) -> Option<Arc<dyn PerRouteConfig>> {
            None
        }
        fn stream_info(&mut self) -> RefMut<'_, StreamInfo> {
            self.stream_info.borrow_mut()
        }
    }

    struct Harness {
        filter: GuardrailFilterInstance,
        registry: Arc<Registry>,
    }

    impl Harness {
        fn new(config: Value) -> Self {
            let registry = StatsControl::new(1).registry();
            let stats = Arc::new(GuardrailStats::new(Some(Arc::clone(&registry)), "test"));
            Harness {
                filter: GuardrailFilterInstance {
                    config: Arc::new(parse_json(config).unwrap()),
                    stats,
                    pending: None,
                    ready: None,
                    decided: false,
                },
                registry,
            }
        }

        /// Drives one request the way the filter manager does: headers, then
        /// the whole body, then (if the filter stopped) its pending check and
        /// `decode_data` again. Returns the final data status.
        async fn decode(&mut self, cb: &mut TestCallbacks, body: &[u8]) -> FilterDataStatus {
            let mut head = RequestHeaders {
                method: Method::POST,
                uri: Uri::from_static("/v1/chat/completions"),
                headers: HeaderMap::new(),
            };
            self.filter.decode_headers(cb, &mut head, false);
            let mut data = Bytes::copy_from_slice(body);
            let status = self.filter.decode_data(cb, &mut data, true);
            if status == FilterDataStatus::Continue || cb.local_reply.is_some() {
                assert!(self.filter.poll_pending().is_none());
                return status;
            }
            assert_eq!(status, FilterDataStatus::StopIterationAndBuffer);
            let pending = self
                .filter
                .poll_pending()
                .expect("a stopped guardrail has its check in flight");
            tokio::time::timeout(TEST_BOUND, pending)
                .await
                .expect("the check is bounded by its own timeout");
            assert_eq!(data.as_ref(), body, "the body is held, not dropped");
            let status = self.filter.decode_data(cb, &mut data, true);
            assert!(
                self.filter.poll_pending().is_none(),
                "one check per request"
            );
            status
        }

        fn count(&self, outcome: &str) -> u64 {
            let scrape = proxy_observability::stats::prometheus_render::render(&self.registry);
            scrape
                .lines()
                .find(|l| {
                    l.contains("llmproxy_guardrail_checks_total{")
                        && l.contains(&format!("outcome=\"{outcome}\""))
                })
                .and_then(|l| l.split_whitespace().last()?.parse().ok())
                .unwrap_or(0)
        }
    }

    fn assert_no_check(rx: &mut mpsc::UnboundedReceiver<Value>) {
        assert!(rx.try_recv().is_err(), "the check must not have been asked");
    }

    // --- decisions ------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn the_check_sees_the_body_tenant_and_both_models_and_an_allow_continues() {
        let (addr, mut rx) = spawn_check(Answering::DenyWhenBodyContains("SECRET")).await;
        let mut h =
            Harness::new(json!({ "default_check": check_json(addr, "FAIL_CLOSED", 2000, 1024) }));
        let mut cb = TestCallbacks::new(Some("acme"), Some("auto"), Some("fast"));
        let body = br#"{"model":"auto","messages":[{"role":"user","content":"hello"}]}"#;

        let status = h.decode(&mut cb, body).await;

        assert_eq!(status, FilterDataStatus::Continue);
        assert!(cb.local_reply.is_none());
        assert_eq!(cb.outcome(), Some("allowed"));
        assert_eq!(
            rx.try_recv().unwrap(),
            json!({
                "tenant": "acme",
                "requested_model": "auto",
                "resolved_model": "fast",
                "body": std::str::from_utf8(body).unwrap(),
            })
        );
        assert_eq!(h.count("allowed"), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_deny_on_body_content_is_a_403_with_the_bounded_reason() {
        let (addr, mut rx) = spawn_check(Answering::DenyWhenBodyContains("SECRET")).await;
        let mut h =
            Harness::new(json!({ "default_check": check_json(addr, "FAIL_OPEN", 2000, 1024) }));
        let mut cb = TestCallbacks::new(Some("acme"), Some("gpt-4o"), None);

        h.decode(
            &mut cb,
            br#"{"model":"gpt-4o","messages":[{"content":"SECRET"}]}"#,
        )
        .await;

        let reply = cb.local_reply.take().expect("a deny is a local reply");
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        assert_eq!(reply.details, "guardrail_denied");
        let body: Value = serde_json::from_str(&reply.body).unwrap();
        assert_eq!(
            body["error"]["message"],
            "request denied by guardrail: the prompt names a secret"
        );
        assert_eq!(cb.outcome(), Some("denied"));
        assert_eq!(rx.try_recv().unwrap()["tenant"], "acme");
        assert_eq!((h.count("denied"), h.count("failure_mode_allowed")), (1, 0));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_tenant_override_replaces_the_default_check() {
        let (default_addr, mut default_rx) =
            spawn_check(Answering::DenyWhenBodyContains("never")).await;
        let (acme_addr, mut acme_rx) = spawn_check(Answering::DenyWhenBodyContains("hello")).await;
        let config = json!({
            "default_check": check_json(default_addr, "FAIL_CLOSED", 2000, 1024),
            "tenants": [{ "tenant": "acme", "check": check_json(acme_addr, "FAIL_CLOSED", 2000, 1024) }],
        });

        let mut h = Harness::new(config.clone());
        let mut acme = TestCallbacks::new(Some("acme"), Some("m"), None);
        h.decode(&mut acme, b"hello").await;
        assert_eq!(acme.outcome(), Some("denied"));
        assert!(acme_rx.try_recv().is_ok());
        assert_no_check(&mut default_rx);

        let mut h = Harness::new(config);
        let mut globex = TestCallbacks::new(Some("globex"), Some("m"), None);
        h.decode(&mut globex, b"hello").await;
        assert_eq!(globex.outcome(), Some("allowed"));
        assert!(default_rx.try_recv().is_ok());
        assert_no_check(&mut acme_rx);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_empty_body_is_not_checked() {
        let (addr, mut rx) = spawn_check(Answering::Status(500)).await;
        let mut h =
            Harness::new(json!({ "default_check": check_json(addr, "FAIL_CLOSED", 2000, 1024) }));
        let mut cb = TestCallbacks::new(Some("acme"), None, None);

        assert_eq!(h.decode(&mut cb, b"").await, FilterDataStatus::Continue);

        assert!(cb.local_reply.is_none());
        assert_eq!(cb.outcome(), None);
        assert_no_check(&mut rx);
    }

    // --- failure modes ----------------------------------------------------------

    /// One failing check per cause; `addr` is where the check points.
    async fn failing(cause: &str) -> (Value, Option<mpsc::UnboundedReceiver<Value>>) {
        match cause {
            "error" => {
                let (addr, rx) = spawn_check(Answering::Status(500)).await;
                (check_json(addr, "", 2000, 1024), Some(rx))
            }
            "refused" => (check_json(closed_port().await, "", 2000, 1024), None),
            "timeout" => {
                let (addr, rx) = spawn_check(Answering::Hang).await;
                (check_json(addr, "", 100, 1024), Some(rx))
            }
            "over_limit" => {
                let (addr, rx) = spawn_check(Answering::DenyWhenBodyContains("x")).await;
                (check_json(addr, "", 2000, 4), Some(rx))
            }
            other => panic!("{other}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fail_closed_refuses_on_error_timeout_and_oversize() {
        let cases = [
            (
                "error",
                "error",
                StatusCode::SERVICE_UNAVAILABLE,
                "guardrail_error",
            ),
            (
                "refused",
                "error",
                StatusCode::SERVICE_UNAVAILABLE,
                "guardrail_error",
            ),
            (
                "timeout",
                "timeout",
                StatusCode::SERVICE_UNAVAILABLE,
                "guardrail_timeout",
            ),
            (
                "over_limit",
                "over_limit",
                StatusCode::PAYLOAD_TOO_LARGE,
                "guardrail_over_limit",
            ),
        ];
        for (cause, outcome, status, details) in cases {
            let (mut check, mut rx) = failing(cause).await;
            check["failure_mode"] = json!("FAIL_CLOSED");
            let mut h = Harness::new(json!({ "default_check": check }));
            let mut cb = TestCallbacks::new(Some("acme"), Some("m"), None);

            h.decode(&mut cb, b"hello").await;

            let reply = cb
                .local_reply
                .take()
                .unwrap_or_else(|| panic!("{cause}: admitted"));
            assert_eq!(
                (reply.status, reply.details.as_str()),
                (status, details),
                "{cause}"
            );
            assert_eq!(cb.outcome(), Some(outcome), "{cause}");
            assert_eq!(h.count(outcome), 1, "{cause}");
            assert_eq!(h.count("failure_mode_allowed"), 0, "{cause}");
            if cause == "over_limit" {
                assert_no_check(rx.as_mut().unwrap());
            }
        }
    }

    /// The fail-open path: each cause admits the request, records the cause
    /// and `failure_mode_allowed`, and marks the access log.
    #[tokio::test(flavor = "multi_thread")]
    async fn fail_open_admits_on_error_timeout_and_oversize_and_counts_each() {
        for (cause, outcome) in [
            ("error", "error"),
            ("refused", "error"),
            ("timeout", "timeout"),
            ("over_limit", "over_limit"),
        ] {
            let (mut check, mut rx) = failing(cause).await;
            check["failure_mode"] = json!("FAIL_OPEN");
            let mut h = Harness::new(json!({ "default_check": check }));
            for _ in 0..2 {
                let mut cb = TestCallbacks::new(Some("acme"), Some("m"), None);
                let status = h.decode(&mut cb, b"hello").await;
                assert_eq!(status, FilterDataStatus::Continue, "{cause}");
                assert!(cb.local_reply.is_none(), "{cause}");
                assert_eq!(cb.outcome(), Some("failure_mode_allowed"), "{cause}");
            }
            assert_eq!(h.count(outcome), 2, "{cause}");
            assert_eq!(h.count("failure_mode_allowed"), 2, "{cause}");
            assert_eq!(h.count("allowed"), 0, "{cause}: a bypass is not an allow");
            if cause == "over_limit" {
                assert_no_check(rx.as_mut().unwrap());
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_https_check_that_fails_the_handshake_is_an_error_not_plaintext() {
        // The server answers plain HTTP at once, so a TLS client must fail the
        // handshake; falling back to plaintext would send the prompt in the
        // clear, and the server would see a JSON request.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n{\"decision\":\"allow\"}",
                    )
                    .await;
                let mut first = [0u8; 1];
                if stream.read(&mut first).await.is_ok() && first[0] == b'{' {
                    let _ = tx.send(Value::Null);
                }
            }
        });
        let mut h = Harness::new(json!({ "default_check": {
            "http": { "uri": format!("https://127.0.0.1:{}/check", addr.port()),
                      "timeout_ms": 2000, "max_body_bytes": 1024 },
            "failure_mode": "FAIL_CLOSED",
        } }));
        let mut cb = TestCallbacks::new(None, None, None);

        h.decode(&mut cb, b"hello").await;

        assert_eq!(cb.outcome(), Some("error"));
        assert_no_check(&mut rx);
    }
}
