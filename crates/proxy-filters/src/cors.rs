//! Envoy v1.38 `envoy.filters.http.cors`.
//!
//! The listener filter's `Cors` message is intentionally empty. Policy lives
//! in `CorsPolicy`, supplied through `typed_per_filter_config`; a listener
//! configuration without policy therefore changes no requests.

use std::sync::Arc;

use http::header::{
    ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
    ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_EXPOSE_HEADERS, ACCESS_CONTROL_MAX_AGE,
    ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD, ORIGIN,
};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use prost_reflect::{DynamicMessage, Value};
use regex::Regex;

use proxy_config::ConfigError;
use proxy_http::filter::{
    DecoderCallbacks, EncoderCallbacks, FactoryContext, FilterHeadersStatus, FilterInstanceFactory,
    HttpFilter, HttpFilterFactory, PerRouteConfig, RequestHeaders, ResponseHeaders,
};

/// Envoy's canonical CORS extension type URL.
pub const TYPE_URL: &str = "type.googleapis.com/envoy.extensions.filters.http.cors.v3.Cors";

// `http` has constants for standard CORS fields but not Chrome's PNA
// extension fields. Keep these typed names beside the other header constants.
const ACCESS_CONTROL_REQUEST_PRIVATE_NETWORK: HeaderName =
    HeaderName::from_static("access-control-request-private-network");
const ACCESS_CONTROL_ALLOW_PRIVATE_NETWORK: HeaderName =
    HeaderName::from_static("access-control-allow-private-network");

fn invalid(field_path: impl Into<String>, reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidValue {
        field_path: field_path.into(),
        reason: reason.into(),
    }
}

/// Compiled form of Envoy's `StringMatcher`, used for `Origin` matching.
#[derive(Debug)]
pub enum OriginMatcher {
    Exact {
        value: String,
        ignore_case: bool,
    },
    Prefix {
        value: String,
        ignore_case: bool,
    },
    Suffix {
        value: String,
        ignore_case: bool,
    },
    Contains {
        value: String,
        ignore_case: bool,
    },
    /// Envoy `safe_regex` is a full-string match, not a substring search.
    SafeRegex(Regex),
}

impl OriginMatcher {
    fn matches(&self, input: &str) -> bool {
        match self {
            Self::Exact { value, ignore_case } if *ignore_case => input.eq_ignore_ascii_case(value),
            Self::Exact { value, .. } => input == value,
            Self::Prefix { value, ignore_case } if *ignore_case => input
                .get(..value.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(value)),
            Self::Prefix { value, .. } => input.starts_with(value),
            Self::Suffix { value, ignore_case } if *ignore_case => {
                input.len() >= value.len()
                    && input.is_char_boundary(input.len() - value.len())
                    && input[input.len() - value.len()..].eq_ignore_ascii_case(value)
            }
            Self::Suffix { value, .. } => input.ends_with(value),
            Self::Contains { value, ignore_case } if *ignore_case => input
                .to_ascii_lowercase()
                .contains(&value.to_ascii_lowercase()),
            Self::Contains { value, .. } => input.contains(value),
            Self::SafeRegex(regex) => regex.is_match(input),
        }
    }
}

/// Fully parsed per-route CORS policy. Header values are parsed while loading
/// config so a malformed value cannot fail a live request.
#[derive(Debug)]
pub struct CorsPolicy {
    allow_origins: Vec<OriginMatcher>,
    allow_methods: Option<HeaderValue>,
    allow_headers: Option<HeaderValue>,
    expose_headers: Option<HeaderValue>,
    max_age: Option<HeaderValue>,
    allow_credentials: bool,
    allow_private_network_access: bool,
    forward_not_matching_preflights: bool,
}

impl CorsPolicy {
    fn origin_allowed(&self, origin: &str) -> bool {
        // This explicit `"*"` probe follows Envoy's C++ filter. It is not
        // equivalent to making every matcher a wildcard: only a matcher that
        // itself accepts `*` grants every origin.
        self.allow_origins
            .iter()
            .any(|matcher| matcher.matches("*") || matcher.matches(origin))
    }
}

/// Parsed `typed_per_filter_config` carrier for this filter.
#[derive(Debug)]
pub struct CorsPerRouteConfig(Arc<CorsPolicy>);

impl CorsPerRouteConfig {
    fn policy(&self) -> Arc<CorsPolicy> {
        Arc::clone(&self.0)
    }
}

impl PerRouteConfig for CorsPerRouteConfig {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn string_field(config: &DynamicMessage, field: &str) -> String {
    config
        .get_field_by_name(field)
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn optional_header_value(
    config: &DynamicMessage,
    field: &str,
) -> Result<Option<HeaderValue>, ConfigError> {
    let value = string_field(config, field);
    if value.is_empty() {
        return Ok(None);
    }
    HeaderValue::from_str(&value).map(Some).map_err(|_| {
        invalid(
            format!("typed_config.{field}"),
            "must be a valid HTTP header value",
        )
    })
}

fn bool_wrapper(config: &DynamicMessage, field: &str, default: bool) -> Result<bool, ConfigError> {
    if !config.has_field_by_name(field) {
        return Ok(default);
    }
    config
        .get_field_by_name(field)
        .and_then(|value| value.as_message().cloned())
        .and_then(|message| message.get_field_by_name("value"))
        .and_then(|value| value.as_bool())
        .ok_or_else(|| invalid(format!("typed_config.{field}.value"), "must be a BoolValue"))
}

fn parse_matcher(config: &DynamicMessage, index: usize) -> Result<OriginMatcher, ConfigError> {
    let field_path = format!("typed_config.allow_origin_string_match[{index}]");
    let ignore_case = config
        .get_field_by_name("ignore_case")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);

    let string_match = |field: &str| string_field(config, field);
    if config.has_field_by_name("exact") {
        return Ok(OriginMatcher::Exact {
            value: string_match("exact"),
            ignore_case,
        });
    }
    if config.has_field_by_name("prefix") {
        let value = string_match("prefix");
        if value.is_empty() {
            return Err(invalid(format!("{field_path}.prefix"), "must not be empty"));
        }
        return Ok(OriginMatcher::Prefix { value, ignore_case });
    }
    if config.has_field_by_name("suffix") {
        let value = string_match("suffix");
        if value.is_empty() {
            return Err(invalid(format!("{field_path}.suffix"), "must not be empty"));
        }
        return Ok(OriginMatcher::Suffix { value, ignore_case });
    }
    if config.has_field_by_name("contains") {
        let value = string_match("contains");
        if value.is_empty() {
            return Err(invalid(
                format!("{field_path}.contains"),
                "must not be empty",
            ));
        }
        return Ok(OriginMatcher::Contains { value, ignore_case });
    }
    if config.has_field_by_name("safe_regex") {
        let regex = config
            .get_field_by_name("safe_regex")
            .and_then(|value| value.as_message().cloned())
            .map(|message| string_field(&message, "regex"))
            .unwrap_or_default();
        if regex.is_empty() {
            return Err(invalid(
                format!("{field_path}.safe_regex.regex"),
                "is required",
            ));
        }
        // Rust's regex engine is linear-time like RE2. Wrap with anchors:
        // `Regex::is_match` otherwise permits a substring, unlike Envoy's
        // StringMatcher safe-regex contract.
        return Regex::new(&format!("^(?:{regex})$"))
            .map(OriginMatcher::SafeRegex)
            .map_err(|error| invalid(format!("{field_path}.safe_regex.regex"), error.to_string()));
    }
    if config.has_field_by_name("custom") {
        return Err(ConfigError::Unimplemented {
            field_path: format!("{field_path}.custom"),
            reason: "custom string matcher extensions are not implemented".to_string(),
        });
    }
    Err(invalid(field_path, "exactly one match pattern is required"))
}

fn reject_runtime_fraction(config: &DynamicMessage, field: &str) -> Result<(), ConfigError> {
    if config.has_field_by_name(field) {
        // This is a deliberate load error, never an ignored rollout knob.
        // WP-31's core policy behavior is deterministic; implementing Envoy
        // runtime-key lookup needs the runtime subsystem, not a fake local RNG.
        return Err(ConfigError::Unimplemented {
            field_path: format!("typed_config.{field}"),
            reason: "runtime fractional CORS enablement is not implemented".to_string(),
        });
    }
    Ok(())
}

/// Parses Envoy v1.38 `CorsPolicy` from a per-route typed config.
pub fn parse_policy(config: &DynamicMessage) -> Result<CorsPolicy, ConfigError> {
    reject_runtime_fraction(config, "filter_enabled")?;
    reject_runtime_fraction(config, "shadow_enabled")?;

    let matchers = config
        .get_field_by_name("allow_origin_string_match")
        .and_then(|value| value.as_list().map(<[_]>::to_vec))
        .unwrap_or_default();
    let mut allow_origins = Vec::with_capacity(matchers.len());
    for (index, matcher) in matchers.iter().enumerate() {
        let matcher = matcher.as_message().cloned().ok_or_else(|| {
            invalid(
                format!("typed_config.allow_origin_string_match[{index}]"),
                "must be a StringMatcher message",
            )
        })?;
        allow_origins.push(parse_matcher(&matcher, index)?);
    }

    Ok(CorsPolicy {
        allow_origins,
        allow_methods: optional_header_value(config, "allow_methods")?,
        allow_headers: optional_header_value(config, "allow_headers")?,
        expose_headers: optional_header_value(config, "expose_headers")?,
        max_age: optional_header_value(config, "max_age")?,
        allow_credentials: bool_wrapper(config, "allow_credentials", false)?,
        allow_private_network_access: bool_wrapper(config, "allow_private_network_access", false)?,
        forward_not_matching_preflights: bool_wrapper(
            config,
            "forward_not_matching_preflights",
            true,
        )?,
    })
}

/// Factory for Envoy's empty listener-level CORS configuration.
#[derive(Default)]
pub struct CorsFilterFactory;

impl HttpFilterFactory for CorsFilterFactory {
    fn type_url(&self) -> &'static str {
        TYPE_URL
    }

    fn may_buffer_response(&self) -> bool {
        false
    }

    fn create(
        &self,
        _config: &DynamicMessage,
        _ctx: &FactoryContext,
    ) -> Result<Box<dyn FilterInstanceFactory>, ConfigError> {
        Ok(Box::new(CorsFilterInstanceFactory))
    }

    fn parse_per_route(
        &self,
        config: &DynamicMessage,
    ) -> Result<Arc<dyn PerRouteConfig>, ConfigError> {
        Ok(Arc::new(CorsPerRouteConfig(Arc::new(parse_policy(
            config,
        )?))))
    }
}

struct CorsFilterInstanceFactory;

impl FilterInstanceFactory for CorsFilterInstanceFactory {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(CorsFilterInstance::default())
    }
}

#[derive(Default)]
struct CorsFilterInstance {
    is_cors_request: bool,
    responded_to_preflight: bool,
    allowed_origin: Option<HeaderValue>,
    policy: Option<Arc<CorsPolicy>>,
}

impl CorsFilterInstance {
    fn reset_for_request(&mut self) {
        self.is_cors_request = false;
        self.responded_to_preflight = false;
        self.allowed_origin = None;
        self.policy = None;
    }

    fn policy_from(cb: &mut dyn DecoderCallbacks) -> Option<Arc<CorsPolicy>> {
        cb.per_route_config().and_then(|config| {
            config
                .as_any()
                .downcast_ref::<CorsPerRouteConfig>()
                .map(CorsPerRouteConfig::policy)
        })
    }

    fn add_credential_header(headers: &mut HeaderMap, policy: &CorsPolicy) {
        if policy.allow_credentials {
            headers.insert(
                ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
        }
    }

    fn preflight_reply(
        cb: &mut dyn DecoderCallbacks,
        policy: Arc<CorsPolicy>,
        allowed_origin: Option<HeaderValue>,
        request_headers: &HeaderMap,
    ) {
        // `HeaderMutationFn` outlives this callback, so it cannot borrow the
        // request map. Copy only the two values Envoy may echo in a wildcard
        // policy before constructing the `Send + 'static` closure.
        let requested_method = request_headers.get(ACCESS_CONTROL_REQUEST_METHOD).cloned();
        let requested_headers = request_headers.get(ACCESS_CONTROL_REQUEST_HEADERS).cloned();
        let private_network_requested = request_headers
            .get(ACCESS_CONTROL_REQUEST_PRIVATE_NETWORK)
            .is_some_and(|value| value == "true");
        cb.send_local_reply(
            StatusCode::OK,
            "",
            Some(Box::new(move |headers| {
                if let Some(origin) = allowed_origin {
                    headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin);
                }
                Self::add_credential_header(headers, &policy);

                if let Some(methods) = &policy.allow_methods {
                    let value = if methods == "*" {
                        requested_method
                            .clone()
                            .unwrap_or_else(|| HeaderValue::from_static(""))
                    } else {
                        methods.clone()
                    };
                    headers.insert(ACCESS_CONTROL_ALLOW_METHODS, value);
                }
                if let Some(allow_headers) = &policy.allow_headers {
                    let value = if allow_headers == "*" {
                        requested_headers
                            .clone()
                            .unwrap_or_else(|| HeaderValue::from_static(""))
                    } else {
                        allow_headers.clone()
                    };
                    headers.insert(ACCESS_CONTROL_ALLOW_HEADERS, value);
                }
                if let Some(max_age) = &policy.max_age {
                    headers.insert(ACCESS_CONTROL_MAX_AGE, max_age.clone());
                }
                if policy.allow_private_network_access && private_network_requested {
                    headers.insert(
                        ACCESS_CONTROL_ALLOW_PRIVATE_NETWORK,
                        HeaderValue::from_static("true"),
                    );
                }
            })),
            "cors_response",
        );
    }
}

impl HttpFilter for CorsFilterInstance {
    fn decode_headers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        self.reset_for_request();
        let Some(policy) = Self::policy_from(cb) else {
            return FilterHeadersStatus::Continue;
        };
        let Some(origin) = headers
            .headers
            .get(ORIGIN)
            .filter(|value| !value.is_empty())
        else {
            return FilterHeadersStatus::Continue;
        };
        let origin_text = match origin.to_str() {
            Ok(origin) => origin,
            // An invalid byte sequence cannot equal a configured StringMatcher.
            Err(_) => "",
        };
        let allowed = policy.origin_allowed(origin_text);
        self.is_cors_request = true;
        self.policy = Some(Arc::clone(&policy));
        if allowed {
            self.allowed_origin = Some(origin.clone());
        }

        let preflight = headers.method == Method::OPTIONS
            && headers
                .headers
                .get(ACCESS_CONTROL_REQUEST_METHOD)
                .is_some_and(|value| !value.is_empty());
        if !preflight || (!allowed && policy.forward_not_matching_preflights) {
            return FilterHeadersStatus::Continue;
        }

        Self::preflight_reply(cb, policy, self.allowed_origin.clone(), &headers.headers);
        // `send_local_reply` begins our filter manager's encoder chain from
        // its top. Envoy's `decoder_callbacks_->encodeHeaders` resumes after
        // this CORS filter, so suppress this instance's normal-response
        // additions when that local preflight reply reaches it again.
        self.responded_to_preflight = true;
        FilterHeadersStatus::Continue
    }

    fn encode_headers(
        &mut self,
        _cb: &mut dyn EncoderCallbacks,
        headers: &mut ResponseHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        if !self.is_cors_request || self.responded_to_preflight {
            return FilterHeadersStatus::Continue;
        }
        let (Some(origin), Some(policy)) = (&self.allowed_origin, &self.policy) else {
            return FilterHeadersStatus::Continue;
        };

        headers
            .headers
            .insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
        Self::add_credential_header(&mut headers.headers, policy);
        if let Some(expose_headers) = &policy.expose_headers {
            headers
                .headers
                .insert(ACCESS_CONTROL_EXPOSE_HEADERS, expose_headers.clone());
        }
        FilterHeadersStatus::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::{RefCell, RefMut};

    use bytes::{Bytes, BytesMut};
    use http::Uri;
    use proxy_config::ir::RouteEntry;
    use proxy_http::filter::{BufferedBody, EncoderCallbacks, HeaderMutationFn};
    use proxy_http::stream_info::StreamInfo;

    fn cors_policy_desc() -> prost_reflect::MessageDescriptor {
        proxy_api::descriptor_pool()
            .get_message_by_name("envoy.extensions.filters.http.cors.v3.CorsPolicy")
            .expect("CORS policy proto is compiled")
    }

    fn string_matcher_desc() -> prost_reflect::MessageDescriptor {
        proxy_api::descriptor_pool()
            .get_message_by_name("envoy.type.matcher.v3.StringMatcher")
            .expect("StringMatcher proto is compiled")
    }

    fn regex_matcher_desc() -> prost_reflect::MessageDescriptor {
        proxy_api::descriptor_pool()
            .get_message_by_name("envoy.type.matcher.v3.RegexMatcher")
            .expect("RegexMatcher proto is compiled")
    }

    fn bool_wrapper_desc() -> prost_reflect::MessageDescriptor {
        proxy_api::descriptor_pool()
            .get_message_by_name("google.protobuf.BoolValue")
            .expect("BoolValue proto is compiled")
    }

    fn matcher(field: &str, value: &str) -> DynamicMessage {
        let mut matcher = DynamicMessage::new(string_matcher_desc());
        matcher.set_field_by_name(field, Value::String(value.to_string()));
        matcher
    }

    fn safe_regex(regex: &str) -> DynamicMessage {
        let mut regex_message = DynamicMessage::new(regex_matcher_desc());
        regex_message.set_field_by_name("regex", Value::String(regex.to_string()));
        let mut matcher = DynamicMessage::new(string_matcher_desc());
        matcher.set_field_by_name("safe_regex", Value::Message(regex_message));
        matcher
    }

    fn bool_value(value: bool) -> DynamicMessage {
        let mut wrapper = DynamicMessage::new(bool_wrapper_desc());
        wrapper.set_field_by_name("value", Value::Bool(value));
        wrapper
    }

    fn policy(matchers: Vec<DynamicMessage>) -> DynamicMessage {
        let mut policy = DynamicMessage::new(cors_policy_desc());
        policy.set_field_by_name(
            "allow_origin_string_match",
            Value::List(matchers.into_iter().map(Value::Message).collect()),
        );
        policy
    }

    fn with_string(mut policy: DynamicMessage, field: &str, value: &str) -> DynamicMessage {
        policy.set_field_by_name(field, Value::String(value.to_string()));
        policy
    }

    fn with_bool(mut policy: DynamicMessage, field: &str, value: bool) -> DynamicMessage {
        policy.set_field_by_name(field, Value::Message(bool_value(value)));
        policy
    }

    struct LocalReply {
        status: StatusCode,
        headers: HeaderMap,
        details: String,
    }

    struct TestCallbacks {
        per_route_config: Option<Arc<dyn PerRouteConfig>>,
        stream_info: RefCell<StreamInfo>,
        local_reply: Option<LocalReply>,
    }

    impl TestCallbacks {
        fn with_policy(policy: CorsPolicy) -> Self {
            Self {
                per_route_config: Some(Arc::new(CorsPerRouteConfig(Arc::new(policy)))),
                stream_info: RefCell::new(StreamInfo::default()),
                local_reply: None,
            }
        }
    }

    impl DecoderCallbacks for TestCallbacks {
        fn send_local_reply(
            &mut self,
            code: StatusCode,
            _body: &str,
            modify_headers: Option<HeaderMutationFn>,
            details: &str,
        ) {
            let mut headers = HeaderMap::new();
            if let Some(modify_headers) = modify_headers {
                modify_headers(&mut headers);
            }
            self.local_reply = Some(LocalReply {
                status: code,
                headers,
                details: details.to_string(),
            });
        }
        fn continue_decoding(&mut self) {
            unimplemented!()
        }
        fn add_decoded_data(&mut self, _data: Bytes, _streaming: bool) {
            unimplemented!()
        }
        fn inject_decoded_data_to_filter_chain(&mut self, _data: Bytes, _end_stream: bool) {
            unimplemented!()
        }
        fn decoding_buffer(&self) -> Option<&BufferedBody> {
            unimplemented!()
        }
        fn modify_decoding_buffer(&mut self, _f: &mut dyn FnMut(&mut BytesMut)) {
            unimplemented!()
        }
        fn route(&mut self) -> Option<Arc<RouteEntry>> {
            None
        }
        fn clear_route_cache(&mut self) {
            unimplemented!()
        }
        fn per_route_config(&mut self) -> Option<Arc<dyn PerRouteConfig>> {
            self.per_route_config.clone()
        }
        fn stream_info(&mut self) -> RefMut<'_, StreamInfo> {
            self.stream_info.borrow_mut()
        }
    }

    impl EncoderCallbacks for TestCallbacks {
        fn continue_encoding(&mut self) {
            unimplemented!()
        }
        fn add_encoded_data(&mut self, _data: Bytes, _streaming: bool) {
            unimplemented!()
        }
        fn inject_encoded_data_to_filter_chain(&mut self, _data: Bytes, _end_stream: bool) {
            unimplemented!()
        }
        fn encoding_buffer(&self) -> Option<&BufferedBody> {
            unimplemented!()
        }
        fn modify_encoding_buffer(&mut self, _f: &mut dyn FnMut(&mut BytesMut)) {
            unimplemented!()
        }
        fn stream_info(&mut self) -> RefMut<'_, StreamInfo> {
            self.stream_info.borrow_mut()
        }
    }

    fn request(
        method: Method,
        origin: Option<&str>,
        preflight_method: Option<&str>,
    ) -> RequestHeaders {
        let mut headers = HeaderMap::new();
        if let Some(origin) = origin {
            headers.insert(ORIGIN, HeaderValue::from_str(origin).unwrap());
        }
        if let Some(preflight_method) = preflight_method {
            headers.insert(
                ACCESS_CONTROL_REQUEST_METHOD,
                HeaderValue::from_str(preflight_method).unwrap(),
            );
        }
        RequestHeaders {
            method,
            uri: Uri::from_static("/"),
            headers,
        }
    }

    fn response() -> ResponseHeaders {
        ResponseHeaders {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
        }
    }

    #[test]
    fn valid_normal_request_adds_origin_credentials_and_exposed_headers() {
        let parsed = parse_policy(&with_bool(
            with_string(
                policy(vec![matcher("exact", "https://web.example")]),
                "expose_headers",
                "x-request-id",
            ),
            "allow_credentials",
            true,
        ))
        .unwrap();
        let mut filter = CorsFilterInstance::default();
        let mut callbacks = TestCallbacks::with_policy(parsed);
        let mut request = request(Method::GET, Some("https://web.example"), None);
        filter.decode_headers(&mut callbacks, &mut request, true);
        let mut response = response();
        filter.encode_headers(&mut callbacks, &mut response, true);

        assert_eq!(
            response.headers[ACCESS_CONTROL_ALLOW_ORIGIN],
            "https://web.example"
        );
        assert_eq!(response.headers[ACCESS_CONTROL_ALLOW_CREDENTIALS], "true");
        assert_eq!(
            response.headers[ACCESS_CONTROL_EXPOSE_HEADERS],
            "x-request-id"
        );
    }

    #[test]
    fn invalid_normal_request_leaves_response_unmodified() {
        let parsed = parse_policy(&policy(vec![matcher("exact", "https://web.example")])).unwrap();
        let mut filter = CorsFilterInstance::default();
        let mut callbacks = TestCallbacks::with_policy(parsed);
        let mut request = request(Method::GET, Some("https://other.example"), None);
        filter.decode_headers(&mut callbacks, &mut request, true);
        let mut response = response();
        filter.encode_headers(&mut callbacks, &mut response, true);
        assert!(response.headers.is_empty());
    }

    #[test]
    fn preflight_is_answered_locally_with_configured_headers() {
        let policy = with_bool(
            with_string(
                with_string(
                    with_string(
                        policy(vec![matcher("exact", "https://web.example")]),
                        "allow_methods",
                        "GET, POST",
                    ),
                    "allow_headers",
                    "content-type",
                ),
                "max_age",
                "3600",
            ),
            "allow_credentials",
            true,
        );
        let parsed = parse_policy(&policy).unwrap();
        let mut filter = CorsFilterInstance::default();
        let mut callbacks = TestCallbacks::with_policy(parsed);
        let mut request = request(Method::OPTIONS, Some("https://web.example"), Some("POST"));
        filter.decode_headers(&mut callbacks, &mut request, true);
        let reply = callbacks.local_reply.unwrap();
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.details, "cors_response");
        assert_eq!(
            reply.headers[ACCESS_CONTROL_ALLOW_ORIGIN],
            "https://web.example"
        );
        assert_eq!(reply.headers[ACCESS_CONTROL_ALLOW_METHODS], "GET, POST");
        assert_eq!(reply.headers[ACCESS_CONTROL_ALLOW_HEADERS], "content-type");
        assert_eq!(reply.headers[ACCESS_CONTROL_MAX_AGE], "3600");
        assert_eq!(reply.headers[ACCESS_CONTROL_ALLOW_CREDENTIALS], "true");
    }

    #[test]
    fn wildcard_preflight_values_echo_requested_method_and_headers() {
        let parsed = parse_policy(&with_string(
            with_string(policy(vec![matcher("exact", "*")]), "allow_methods", "*"),
            "allow_headers",
            "*",
        ))
        .unwrap();
        let mut filter = CorsFilterInstance::default();
        let mut callbacks = TestCallbacks::with_policy(parsed);
        let mut request = request(Method::OPTIONS, Some("https://web.example"), Some("PATCH"));
        request.headers.insert(
            ACCESS_CONTROL_REQUEST_HEADERS,
            HeaderValue::from_static("x-api-key, content-type"),
        );
        filter.decode_headers(&mut callbacks, &mut request, true);
        let reply = callbacks.local_reply.unwrap();
        assert_eq!(reply.headers[ACCESS_CONTROL_ALLOW_METHODS], "PATCH");
        assert_eq!(
            reply.headers[ACCESS_CONTROL_ALLOW_HEADERS],
            "x-api-key, content-type"
        );
    }

    #[test]
    fn invalid_preflight_forwards_by_default_but_can_be_handled_locally() {
        let mut request = request(Method::OPTIONS, Some("https://other.example"), Some("GET"));
        let mut filter = CorsFilterInstance::default();
        let mut callbacks = TestCallbacks::with_policy(
            parse_policy(&policy(vec![matcher("exact", "https://web.example")])).unwrap(),
        );
        filter.decode_headers(&mut callbacks, &mut request, true);
        assert!(callbacks.local_reply.is_none());

        let mut filter = CorsFilterInstance::default();
        let mut callbacks = TestCallbacks::with_policy(
            parse_policy(&with_bool(
                policy(vec![matcher("exact", "https://web.example")]),
                "forward_not_matching_preflights",
                false,
            ))
            .unwrap(),
        );
        filter.decode_headers(&mut callbacks, &mut request, true);
        let reply = callbacks.local_reply.unwrap();
        assert_eq!(reply.status, StatusCode::OK);
        assert!(reply.headers.get(ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
    }

    #[test]
    fn all_string_matcher_kinds_are_honored_and_safe_regex_is_anchored() {
        let mut exact = matcher("exact", "HTTPS://EXACT.EXAMPLE");
        exact.set_field_by_name("ignore_case", Value::Bool(true));
        let matchers = vec![
            exact,
            matcher("prefix", "https://prefix."),
            matcher("suffix", ".suffix.example"),
            matcher("contains", ".contains."),
            safe_regex("https://regex\\.example/[0-9]+"),
        ];
        let parsed = parse_policy(&policy(matchers)).unwrap();
        for origin in [
            "https://exact.example",
            "https://prefix.anything",
            "https://anything.suffix.example",
            "https://x.contains.y",
            "https://regex.example/42",
        ] {
            assert!(parsed.origin_allowed(origin), "{origin}");
        }
        assert!(!parsed.origin_allowed("prefix https://regex.example/42 suffix"));
    }

    #[test]
    fn malformed_and_unimplemented_policy_fields_error_with_full_path() {
        let error = parse_policy(&policy(vec![matcher("prefix", "")])).unwrap_err();
        assert!(
            matches!(error, ConfigError::InvalidValue { field_path, .. } if field_path == "typed_config.allow_origin_string_match[0].prefix")
        );

        let mut config = policy(vec![matcher("exact", "*")]);
        let runtime = DynamicMessage::new(
            proxy_api::descriptor_pool()
                .get_message_by_name("envoy.config.core.v3.RuntimeFractionalPercent")
                .unwrap(),
        );
        config.set_field_by_name("filter_enabled", Value::Message(runtime));
        let error = parse_policy(&config).unwrap_err();
        assert!(
            matches!(error, ConfigError::Unimplemented { field_path, .. } if field_path == "typed_config.filter_enabled")
        );
    }

    #[test]
    fn private_network_preflight_is_opt_in() {
        let parsed = parse_policy(&with_bool(
            policy(vec![matcher("exact", "*")]),
            "allow_private_network_access",
            true,
        ))
        .unwrap();
        let mut filter = CorsFilterInstance::default();
        let mut callbacks = TestCallbacks::with_policy(parsed);
        let mut request = request(Method::OPTIONS, Some("https://web.example"), Some("GET"));
        request.headers.insert(
            ACCESS_CONTROL_REQUEST_PRIVATE_NETWORK,
            HeaderValue::from_static("true"),
        );
        filter.decode_headers(&mut callbacks, &mut request, true);
        let reply = callbacks.local_reply.unwrap();
        assert_eq!(reply.headers[ACCESS_CONTROL_ALLOW_PRIVATE_NETWORK], "true");
    }
}
