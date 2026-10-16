//! `llmproxy.model_resolver`: resolves the reserved model name `auto` to a
//! configured model alias.
//!
//! It reads tenant identity from auth and the requested model from
//! `body_rewrite`; config validation enforces that order and places
//! `model_authz` afterward. For `auto`, it publishes the resolved alias and
//! updates the routing header, while the router rewrites the body after the
//! upstream cluster is selected. Authorization checks the alias, and usage
//! retains the original request model (AGENTS.md "Policy Domains").
//!
//! Resolution runs after request data is available, at end-of-stream or
//! trailers. Missing rules without a default are refused; a configured default
//! still passes through model authorization.

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use http::StatusCode;
use prost_reflect::DynamicMessage;
use proxy_config::ConfigError;
use proxy_http::filter::{
    DecoderCallbacks, FactoryContext, FilterDataStatus, FilterHeadersStatus, FilterInstanceFactory,
    FilterTrailersStatus, HttpFilter, HttpFilterFactory, RequestHeaders, RequestTrailers,
};

use crate::body_rewrite_filter::apply_model_header;

/// Type URL this filter is registered under.
pub const TYPE_URL: &str = "type.llmproxy.dev/llmproxy.filters.v0.ModelResolver";

/// The reserved model name that triggers resolution.
pub const AUTO_MODEL: &str = "auto";

/// `%RESPONSE_CODE_DETAILS%` for a request this filter refuses.
const NOT_CONFIGURED_DETAILS: &str = "auto_model_not_configured";

fn invalid(field_path: impl Into<String>, reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidValue {
        field_path: field_path.into(),
        reason: reason.into(),
    }
}

/// A resolved model must be a concrete alias: resolving to `auto` would loop,
/// and a glob names no single model.
fn validate_model(raw: &str, field_path: &str) -> Result<(), ConfigError> {
    if raw.is_empty() {
        return Err(invalid(field_path, "must not be empty"));
    }
    if raw == AUTO_MODEL {
        return Err(invalid(
            field_path,
            "must not be `auto`; a resolver must resolve to a concrete model alias",
        ));
    }
    if raw.contains('*') {
        return Err(invalid(
            field_path,
            "must be a concrete model alias, not a pattern",
        ));
    }
    Ok(())
}

/// Parsed in-process rules.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct StaticModelRules {
    default_model: Option<String>,
    tenants: HashMap<String, String>,
}

impl StaticModelRules {
    /// The alias for `tenant`: its own rule, otherwise the default.
    fn resolve(&self, tenant: Option<&str>) -> Option<&str> {
        tenant
            .and_then(|tenant| self.tenants.get(tenant))
            .or(self.default_model.as_ref())
            .map(String::as_str)
    }
}

/// Parses `typed_config`. Every field maps to the parsed rules or fails with
/// its dotted path (AGENTS.md invariant 1).
pub fn parse_config(config: &DynamicMessage) -> Result<StaticModelRules, ConfigError> {
    if !config.has_field_by_name("rules") {
        return Err(invalid(
            "typed_config.rules",
            "a resolver is required; `rules` is the only resolver supported",
        ));
    }
    let rules = config
        .get_field_by_name("rules")
        .and_then(|v| v.as_message().cloned())
        .ok_or_else(|| invalid("typed_config.rules", "must be a message"))?;

    let default_model = rules
        .get_field_by_name("default_model")
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    let default_model = if default_model.is_empty() {
        None
    } else {
        validate_model(&default_model, "typed_config.rules.default_model")?;
        Some(default_model)
    };

    let entries = rules
        .get_field_by_name("tenants")
        .and_then(|v| v.as_list().map(<[_]>::to_vec))
        .unwrap_or_default();
    let mut tenants = HashMap::with_capacity(entries.len());
    let mut seen: HashMap<String, usize> = HashMap::new();
    for (i, entry) in entries.iter().enumerate() {
        let path = format!("typed_config.rules.tenants[{i}]");
        let msg = entry
            .as_message()
            .ok_or_else(|| invalid(&path, "must be a message"))?;
        let field = |name: &str| {
            msg.get_field_by_name(name)
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default()
        };
        let tenant = field("tenant");
        if tenant.is_empty() {
            return Err(invalid(format!("{path}.tenant"), "must not be empty"));
        }
        if let Some(&first) = seen.get(&tenant) {
            return Err(invalid(
                format!("{path}.tenant"),
                format!("duplicate `tenant`; already configured at index {first}"),
            ));
        }
        let model = field("model");
        validate_model(&model, &format!("{path}.model"))?;
        seen.insert(tenant.clone(), i);
        tenants.insert(tenant, model);
    }

    Ok(StaticModelRules {
        default_model,
        tenants,
    })
}

#[derive(Default)]
pub struct ModelResolverFilterFactory;

impl HttpFilterFactory for ModelResolverFilterFactory {
    fn type_url(&self) -> &'static str {
        TYPE_URL
    }

    fn may_buffer_response(&self) -> bool {
        false
    }

    fn create(
        &self,
        config: &DynamicMessage,
        _ctx: &FactoryContext,
    ) -> Result<Box<dyn FilterInstanceFactory>, ConfigError> {
        Ok(Box::new(ModelResolverInstanceFactory {
            rules: Arc::new(parse_config(config)?),
        }))
    }
}

struct ModelResolverInstanceFactory {
    rules: Arc<StaticModelRules>,
}

impl FilterInstanceFactory for ModelResolverInstanceFactory {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(ModelResolverFilterInstance {
            rules: Arc::clone(&self.rules),
            decided: false,
        })
    }
}

struct ModelResolverFilterInstance {
    rules: Arc<StaticModelRules>,
    decided: bool,
}

impl ModelResolverFilterInstance {
    /// Idempotent via `self.decided`: a chunked body ends with `end_stream`,
    /// and a trailered request reaches `decode_trailers` instead.
    fn resolve(&mut self, cb: &mut dyn DecoderCallbacks) {
        if self.decided {
            return;
        }
        self.decided = true;

        // Rust note: clone out and drop the `RefMut` guard before any other
        // call on `cb`; `stream_info()` must not be held across one.
        let (tenant, requested) = {
            let info = cb.stream_info();
            (info.auth.tenant.clone(), info.requested_model.clone())
        };
        if requested.as_deref() != Some(AUTO_MODEL) {
            return;
        }

        let Some(model) = self.rules.resolve(tenant.as_deref()).map(str::to_owned) else {
            tracing::debug!(
                tenant = tenant.as_deref().unwrap_or("-"),
                "model_resolver: no rule and no default_model for `auto`"
            );
            cb.send_local_reply(
                StatusCode::BAD_REQUEST,
                "no model is configured for `auto`",
                None,
                NOT_CONFIGURED_DETAILS,
            );
            return;
        };

        {
            cb.stream_info().resolved_model = Some(model.clone());
        }
        cb.modify_decoded_headers(&mut |headers: &mut RequestHeaders| {
            apply_model_header(&mut headers.headers, Some(&model));
        });
        cb.clear_route_cache();
    }
}

impl HttpFilter for ModelResolverFilterInstance {
    fn decode_headers(
        &mut self,
        _cb: &mut dyn DecoderCallbacks,
        _headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        // An instance serves one stream in production; resetting here keeps
        // the latch honest if one is ever reused.
        self.decided = false;
        FilterHeadersStatus::Continue
    }

    fn decode_data(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        _data: &mut Bytes,
        end_stream: bool,
    ) -> FilterDataStatus {
        if end_stream {
            self.resolve(cb);
        }
        FilterDataStatus::Continue
    }

    /// A trailered request never sees `end_stream` on data.
    fn decode_trailers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        _trailers: &mut RequestTrailers,
    ) -> FilterTrailersStatus {
        self.resolve(cb);
        FilterTrailersStatus::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::{RefCell, RefMut};

    use http::{HeaderMap, HeaderValue, Method, Uri};
    use proxy_config::ir::RouteEntry;
    use proxy_http::filter::{BufferedBody, HeaderMutationFn, PerRouteConfig};
    use proxy_http::stream_info::StreamInfo;

    use crate::body_rewrite_filter::MODEL_HEADER_NAME;

    // --- config scaffolding ---------------------------------------------------

    fn desc(name: &str) -> prost_reflect::MessageDescriptor {
        proxy_api::descriptor_pool()
            .get_message_by_name(&format!("llmproxy.filters.v0.{name}"))
            .unwrap_or_else(|| panic!("{name} is compiled into proxy-api"))
    }

    fn config(default_model: &str, tenants: &[(&str, &str)]) -> DynamicMessage {
        let mut rules = DynamicMessage::new(desc("StaticModelRules"));
        rules.set_field_by_name(
            "default_model",
            prost_reflect::Value::String(default_model.to_string()),
        );
        rules.set_field_by_name(
            "tenants",
            prost_reflect::Value::List(
                tenants
                    .iter()
                    .map(|(tenant, model)| {
                        let mut rule = DynamicMessage::new(desc("TenantModelRule"));
                        rule.set_field_by_name(
                            "tenant",
                            prost_reflect::Value::String(tenant.to_string()),
                        );
                        rule.set_field_by_name(
                            "model",
                            prost_reflect::Value::String(model.to_string()),
                        );
                        prost_reflect::Value::Message(rule)
                    })
                    .collect(),
            ),
        );
        let mut msg = DynamicMessage::new(desc("ModelResolver"));
        msg.set_field_by_name("rules", prost_reflect::Value::Message(rules));
        msg
    }

    fn field_path(err: ConfigError) -> String {
        match err {
            ConfigError::InvalidValue { field_path, .. } => field_path,
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    // --- config parsing ---------------------------------------------------------

    #[test]
    fn a_missing_resolver_is_a_load_error() {
        let err = parse_config(&DynamicMessage::new(desc("ModelResolver")))
            .expect_err("no resolver must not load as a resolver that never resolves");
        assert_eq!(field_path(err), "typed_config.rules");
    }

    #[test]
    fn an_empty_tenant_reports_its_path() {
        let err = parse_config(&config("", &[("", "fast")])).unwrap_err();
        assert_eq!(field_path(err), "typed_config.rules.tenants[0].tenant");
    }

    #[test]
    fn a_duplicate_tenant_reports_the_second_index() {
        let err = parse_config(&config("", &[("acme", "fast"), ("acme", "slow")])).unwrap_err();
        assert_eq!(field_path(err), "typed_config.rules.tenants[1].tenant");
    }

    #[test]
    fn an_empty_tenant_model_reports_its_path() {
        let err = parse_config(&config("", &[("acme", "")])).unwrap_err();
        assert_eq!(field_path(err), "typed_config.rules.tenants[0].model");
    }

    #[test]
    fn resolving_to_auto_or_a_pattern_is_rejected() {
        let err = parse_config(&config("auto", &[])).unwrap_err();
        assert_eq!(field_path(err), "typed_config.rules.default_model");
        let err = parse_config(&config("", &[("acme", "gpt-4*")])).unwrap_err();
        assert_eq!(field_path(err), "typed_config.rules.tenants[0].model");
    }

    // --- request scaffolding --------------------------------------------------

    struct LocalReply {
        status: StatusCode,
        details: String,
    }

    struct TestCallbacks {
        stream_info: RefCell<StreamInfo>,
        headers: RequestHeaders,
        local_reply: Option<LocalReply>,
        route_cache_clears: usize,
    }

    impl TestCallbacks {
        fn new(tenant: Option<&str>, requested_model: Option<&str>) -> Self {
            let mut info = StreamInfo::default();
            info.auth.tenant = tenant.map(str::to_owned);
            info.requested_model = requested_model.map(str::to_owned);
            let mut headers = HeaderMap::new();
            if let Some(model) = requested_model {
                headers.insert(MODEL_HEADER_NAME, HeaderValue::from_str(model).unwrap());
            }
            TestCallbacks {
                stream_info: RefCell::new(info),
                headers: RequestHeaders {
                    method: Method::POST,
                    uri: Uri::from_static("/v1/chat/completions"),
                    headers,
                },
                local_reply: None,
                route_cache_clears: 0,
            }
        }

        fn model_header(&self) -> Option<&str> {
            self.headers
                .headers
                .get(MODEL_HEADER_NAME)
                .and_then(|v| v.to_str().ok())
        }

        fn resolved_model(&self) -> Option<String> {
            self.stream_info.borrow().resolved_model.clone()
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
            assert!(modify_headers.is_none());
            self.local_reply = Some(LocalReply {
                status: code,
                details: details.to_string(),
            });
        }
        fn continue_decoding(&mut self) {
            unimplemented!("model_resolver_filter never stops iteration")
        }
        fn add_decoded_data(&mut self, _data: Bytes, _streaming: bool) {
            unimplemented!("model_resolver_filter never buffers request data")
        }
        fn inject_decoded_data_to_filter_chain(&mut self, _data: Bytes, _end_stream: bool) {
            unimplemented!("model_resolver_filter never injects data")
        }
        fn decoding_buffer(&self) -> Option<&BufferedBody> {
            unimplemented!("model_resolver_filter never consults the decoding buffer")
        }
        fn modify_decoding_buffer(&mut self, _f: &mut dyn FnMut(&mut bytes::BytesMut)) {
            unimplemented!("model_resolver_filter never touches request bytes")
        }
        fn modify_decoded_headers(&mut self, f: &mut dyn FnMut(&mut RequestHeaders)) -> bool {
            f(&mut self.headers);
            true
        }
        fn route(&mut self) -> Option<Arc<RouteEntry>> {
            None
        }
        fn clear_route_cache(&mut self) {
            self.route_cache_clears += 1;
        }
        fn per_route_config(&mut self) -> Option<Arc<dyn PerRouteConfig>> {
            None
        }
        fn stream_info(&mut self) -> RefMut<'_, StreamInfo> {
            self.stream_info.borrow_mut()
        }
    }

    fn filter(default_model: &str, tenants: &[(&str, &str)]) -> ModelResolverFilterInstance {
        ModelResolverFilterInstance {
            rules: Arc::new(parse_config(&config(default_model, tenants)).unwrap()),
            decided: false,
        }
    }

    fn decode(filter: &mut ModelResolverFilterInstance, cb: &mut TestCallbacks) {
        let mut head = RequestHeaders {
            method: Method::POST,
            uri: Uri::from_static("/v1/chat/completions"),
            headers: HeaderMap::new(),
        };
        filter.decode_headers(cb, &mut head, false);
        filter.decode_data(cb, &mut Bytes::new(), true);
    }

    // --- resolution -------------------------------------------------------------

    #[test]
    fn auto_resolves_to_the_tenants_own_rule() {
        let mut filter = filter("fast", &[("acme", "claude-sonnet")]);
        let mut cb = TestCallbacks::new(Some("acme"), Some("auto"));

        decode(&mut filter, &mut cb);

        assert!(cb.local_reply.is_none());
        assert_eq!(cb.resolved_model().as_deref(), Some("claude-sonnet"));
        assert_eq!(cb.model_header(), Some("claude-sonnet"));
        assert_eq!(cb.route_cache_clears, 1, "routing must re-match the alias");
        assert_eq!(
            cb.stream_info.borrow().requested_model.as_deref(),
            Some("auto"),
            "requested_model keeps what the client sent"
        );
    }

    #[test]
    fn a_tenant_without_a_rule_gets_the_default() {
        let mut filter = filter("fast", &[("acme", "claude-sonnet")]);
        let mut cb = TestCallbacks::new(Some("globex"), Some("auto"));

        decode(&mut filter, &mut cb);

        assert!(cb.local_reply.is_none());
        assert_eq!(cb.resolved_model().as_deref(), Some("fast"));
        assert_eq!(cb.model_header(), Some("fast"));
    }

    #[test]
    fn no_rule_and_no_default_is_refused_with_400() {
        let mut filter = filter("", &[("acme", "claude-sonnet")]);
        let mut cb = TestCallbacks::new(Some("globex"), Some("auto"));

        decode(&mut filter, &mut cb);

        let reply = cb
            .local_reply
            .take()
            .expect("unset must never route to a guess");
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert_eq!(reply.details, NOT_CONFIGURED_DETAILS);
        assert_eq!(cb.resolved_model(), None);
        assert_eq!(cb.model_header(), Some("auto"));
    }

    #[test]
    fn no_tenant_gets_the_default_or_is_refused() {
        let mut with_default = filter("fast", &[("acme", "claude-sonnet")]);
        let mut cb = TestCallbacks::new(None, Some("auto"));
        decode(&mut with_default, &mut cb);
        assert!(cb.local_reply.is_none());
        assert_eq!(cb.resolved_model().as_deref(), Some("fast"));

        let mut without_default = filter("", &[("acme", "claude-sonnet")]);
        let mut cb = TestCallbacks::new(None, Some("auto"));
        decode(&mut without_default, &mut cb);
        assert_eq!(
            cb.local_reply.map(|r| r.status),
            Some(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn a_concrete_model_passes_through_untouched() {
        let mut filter = filter("fast", &[("acme", "claude-sonnet")]);
        let mut cb = TestCallbacks::new(Some("acme"), Some("gpt-4o"));

        decode(&mut filter, &mut cb);

        assert!(cb.local_reply.is_none());
        assert_eq!(cb.resolved_model(), None);
        assert_eq!(cb.model_header(), Some("gpt-4o"));
        assert_eq!(cb.route_cache_clears, 0);
    }

    #[test]
    fn a_request_with_no_model_passes_through() {
        let mut filter = filter("fast", &[]);
        let mut cb = TestCallbacks::new(Some("acme"), None);

        decode(&mut filter, &mut cb);

        assert!(cb.local_reply.is_none());
        assert_eq!(cb.resolved_model(), None);
    }

    #[test]
    fn a_trailered_request_is_resolved_via_decode_trailers() {
        let mut filter = filter("fast", &[]);
        let mut cb = TestCallbacks::new(Some("acme"), Some("auto"));
        let mut head = RequestHeaders {
            method: Method::POST,
            uri: Uri::from_static("/v1/chat/completions"),
            headers: HeaderMap::new(),
        };
        filter.decode_headers(&mut cb, &mut head, false);
        filter.decode_data(&mut cb, &mut Bytes::new(), false);
        assert_eq!(
            cb.resolved_model(),
            None,
            "not decided before end of stream"
        );

        filter.decode_trailers(&mut cb, &mut RequestTrailers(HeaderMap::new()));

        assert_eq!(cb.resolved_model().as_deref(), Some("fast"));
    }
}
