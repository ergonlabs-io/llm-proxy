//! A minimal built-in HTTP filter that adds one configured header to every
//! response. It exists to exercise the `FilterRegistry` -> `FilterChainHandler`
//! wiring in `listener.rs` end to end -- see `hcm_filter_chain_mutates_headers_over_the_real_socket`
//! in that module's tests, which fails without a real registry + factory
//! behind the HCM terminal filter.
//!
//! Rust note on the type URL: rather than vendoring a brand-new Envoy-style
//! proto in `proxy-api` just for this one built-in, `typed_config` reuses the
//! shape of the already-compiled `envoy.config.core.v3.HeaderValueOption`
//! message (`header.key` / `header.value`) -- an Any's type URL is just an
//! opaque `prefix/full.type.name` string, and only the suffix has to resolve
//! against the descriptor pool (see `proxy-config::lower::decode_http_filter_config`),
//! so pointing our `type.llmproxy.dev` prefix at that existing message name is
//! legal, if a little unusual. A real `llmproxy.*` filter would get its own vendored
//! proto; this one is deliberately the smallest thing that proves the path.

use std::sync::Arc;

use http::{HeaderName, HeaderValue};
use prost_reflect::DynamicMessage;

use proxy_config::ConfigError;
use proxy_http::filter::{
    EncoderCallbacks, FactoryContext, FilterHeadersStatus, FilterInstanceFactory, HttpFilter,
    HttpFilterFactory, ResponseHeaders,
};

/// Type URL this filter is registered under (see the module doc for the
/// `HeaderValueOption`-reuse rationale).
pub const TYPE_URL: &str = "type.llmproxy.dev/envoy.config.core.v3.HeaderValueOption";

/// Parsed, validated config: the single header key/value this filter adds to
/// every response passing through it.
#[derive(Debug)]
struct HeaderMutationConfig {
    name: HeaderName,
    value: HeaderValue,
}

/// [`HttpFilterFactory`] for [`TYPE_URL`] -- one of these is built once per
/// listener wiring (`build_hcm_handler`), independent of the shared
/// [`proxy_http::filter::FilterRegistry`] it's registered into.
#[derive(Default)]
pub struct HeaderMutationFactory;

impl HttpFilterFactory for HeaderMutationFactory {
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
        let cfg = parse_config(config)?;
        Ok(Box::new(HeaderMutationInstanceFactory {
            cfg: Arc::new(cfg),
        }))
    }
}

fn parse_config(config: &DynamicMessage) -> Result<HeaderMutationConfig, ConfigError> {
    let invalid = |field_path: &str, reason: String| ConfigError::InvalidValue {
        field_path: field_path.to_string(),
        reason,
    };

    let header = config
        .get_field_by_name("header")
        .and_then(|v| v.as_message().cloned())
        .ok_or_else(|| {
            invalid(
                "typed_config.header",
                "the `header` field is required".to_string(),
            )
        })?;

    let key = header
        .get_field_by_name("key")
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    let value = header
        .get_field_by_name("value")
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();

    let name = HeaderName::from_bytes(key.as_bytes()).map_err(|e| {
        invalid(
            "typed_config.header.key",
            format!("invalid header name `{key}`: {e}"),
        )
    })?;
    let value = HeaderValue::from_str(&value).map_err(|e| {
        invalid(
            "typed_config.header.value",
            format!("invalid header value `{value}`: {e}"),
        )
    })?;

    Ok(HeaderMutationConfig { name, value })
}

struct HeaderMutationInstanceFactory {
    cfg: Arc<HeaderMutationConfig>,
}

impl FilterInstanceFactory for HeaderMutationInstanceFactory {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(HeaderMutationFilterInstance {
            cfg: self.cfg.clone(),
        })
    }
}

/// Per-stream instance (fresh one per request, per the frozen `HttpFilter`
/// contract -- see `filter.rs`'s module doc). Stateless beyond the shared,
/// `Arc`'d config, so cloning it per stream is cheap.
struct HeaderMutationFilterInstance {
    cfg: Arc<HeaderMutationConfig>,
}

impl HttpFilter for HeaderMutationFilterInstance {
    fn encode_headers(
        &mut self,
        _cb: &mut dyn EncoderCallbacks,
        headers: &mut ResponseHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        headers
            .headers
            .insert(self.cfg.name.clone(), self.cfg.value.clone());
        FilterHeadersStatus::Continue
    }
}

/// Build a `HeaderValueOption`-shaped `DynamicMessage` the same way the real
/// lowering pipeline would decode one from an Any's bytes -- shared by this
/// module's own tests and by `listener.rs`'s end-to-end filter-chain test,
/// which needs a realistic `HttpFilterSpec::config` for [`TYPE_URL`] without
/// going through a full YAML bootstrap.
#[cfg(test)]
pub(crate) fn header_value_option(key: &str, value: &str) -> DynamicMessage {
    let hv_desc = proxy_api::descriptor_pool()
        .get_message_by_name("envoy.config.core.v3.HeaderValue")
        .expect("HeaderValue is compiled into proxy-api");
    let mut hv = DynamicMessage::new(hv_desc);
    hv.set_field_by_name("key", prost_reflect::Value::String(key.to_string()));
    hv.set_field_by_name("value", prost_reflect::Value::String(value.to_string()));

    let hvo_desc = proxy_api::descriptor_pool()
        .get_message_by_name("envoy.config.core.v3.HeaderValueOption")
        .expect("HeaderValueOption is compiled into proxy-api");
    let mut hvo = DynamicMessage::new(hvo_desc);
    hvo.set_field_by_name("header", prost_reflect::Value::Message(hv));
    hvo
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_key_and_value() {
        let config = header_value_option("x-mutated", "yes");
        let cfg = parse_config(&config).expect("valid config");
        assert_eq!(cfg.name, HeaderName::from_static("x-mutated"));
        assert_eq!(cfg.value, HeaderValue::from_static("yes"));
    }

    #[test]
    fn missing_header_field_is_rejected() {
        let hvo_desc = proxy_api::descriptor_pool()
            .get_message_by_name("envoy.config.core.v3.HeaderValueOption")
            .expect("HeaderValueOption is compiled into proxy-api");
        let config = DynamicMessage::new(hvo_desc);
        let err = parse_config(&config).expect_err("missing header must fail");
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn invalid_header_name_is_rejected() {
        let config = header_value_option("not a valid name", "yes");
        let err = parse_config(&config).expect_err("invalid header name must fail");
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn factory_creates_filter_that_inserts_the_header() {
        let config = header_value_option("x-mutated", "yes");
        let factory = HeaderMutationFactory;
        let instance_factory = factory
            .create(&config, &FactoryContext::default())
            .expect("valid config builds a factory");
        let mut filter = instance_factory.create_filter();

        struct NoopEncoderCallbacks(std::cell::RefCell<proxy_http::stream_info::StreamInfo>);
        impl EncoderCallbacks for NoopEncoderCallbacks {
            fn continue_encoding(&mut self) {}
            fn add_encoded_data(&mut self, _data: bytes::Bytes, _streaming: bool) {}
            fn inject_encoded_data_to_filter_chain(
                &mut self,
                _data: bytes::Bytes,
                _end_stream: bool,
            ) {
            }
            fn encoding_buffer(&self) -> Option<&proxy_http::filter::BufferedBody> {
                None
            }
            fn modify_encoding_buffer(&mut self, _f: &mut dyn FnMut(&mut bytes::BytesMut)) {}
            fn stream_info(
                &mut self,
            ) -> std::cell::RefMut<'_, proxy_http::stream_info::StreamInfo> {
                self.0.borrow_mut()
            }
        }
        let mut cb = NoopEncoderCallbacks(std::cell::RefCell::new(
            proxy_http::stream_info::StreamInfo::default(),
        ));
        let mut headers = ResponseHeaders {
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
        };
        let status = filter.encode_headers(&mut cb, &mut headers, true);
        assert_eq!(status, FilterHeadersStatus::Continue);
        assert_eq!(headers.headers.get("x-mutated").unwrap(), "yes");
    }
}
