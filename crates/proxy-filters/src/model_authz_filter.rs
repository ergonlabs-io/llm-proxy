//! WP-50 increment 3a — wires [`crate::model_authz`]'s `ModelAccess`/
//! `ModelPattern` matcher into a real decode-path `HttpFilter`:
//! `llmproxy.model_authz`. See `internal-docs/wp-50-inc3-design-brief.md`'s
//! "3a" and "The load-bearing seam" sections, which are normative here.
//!
//! # Decode-path only, and it must run LAST among the Lane-H filters it needs
//!
//! This filter needs two facts that only exist once two OTHER decode-path
//! filters have already run: `StreamInfo::auth.tenant` (written by
//! `llmproxy.auth`) and `StreamInfo::requested_model` (written by
//! `llmproxy.body_rewrite`). Decoder callbacks run in **config order**
//! (S2.1), so both of those filters must be configured BEFORE
//! `llmproxy.model_authz` in a listener's `http_filters` list.
//! `proxy_config::lower::check_lane_h_filter_order` rejects the wrong order
//! at config load, with an error explaining why -- see that function's doc.
//! Get it backwards and this filter reads `None` for whichever fact came
//! from the reordered filter and refuses EVERY request (see the next
//! section), which is at least loud, unlike the two existing Lane-H ordering
//! traps this one joins (`token_limit_filter`'s module doc).
//!
//! # Fail closed on BOTH missing inputs; fail closed on an unknown tenant too
//!
//! Three ways this filter refuses a request, all with the SAME wire response
//! and the SAME generic `%RESPONSE_CODE_DETAILS%` (`model_not_permitted` --
//! never naming which of the three applied, and never rendering a policy's
//! contents or a tenant's allow-list, per the design brief):
//!
//! 1. **No authenticated tenant** (`StreamInfo::auth.tenant` is `None`) -- an
//!    unauthenticated stream cannot be authorized against a per-tenant
//!    policy. This is the authentic**ation** axis (fails closed, always),
//!    not the authoriz**ation** axis below -- see
//!    `crate::auth::TenantPolicy`'s doc for why the two must not be confused.
//! 2. **No requested model** (`StreamInfo::requested_model` is `None`) -- a
//!    body with no extractable `model` cannot be checked against a model
//!    allow-list.
//! 3. **An authenticated tenant absent from THIS filter's configured
//!    `policies`** -- deliberately NOT an implicit "no restriction, allow
//!    everything". Authorization defaults open in this codebase (an
//!    authenticated tenant with NO policy configured anywhere may use every
//!    model), but that default lives in "this filter is not in the chain at
//!    all" -- see [`TYPE_URL`]'s module-level framing and the proto's own
//!    doc. Once an operator DOES configure this filter, a tenant missing
//!    from its `policies` is a config/consistency error to refuse, not a
//!    gap to paper over; see the design brief's "Authorization default is
//!    OPEN; authentication default is CLOSED" section.
//!
//! Case 3 is genuinely different from 1/2 in kind (a resolved identity this
//! filter's own config simply doesn't cover, vs. two missing prerequisites),
//! but it gets the same wire response and detail string on purpose: the
//! acceptance criteria call for a single generic denial, and finer-grained
//! detail strings would themselves start to describe the policy shape (e.g.
//! "no policy for this tenant" leaks that policies are per-tenant and this
//! tenant has none) to a caller who is, by definition, not authorized to see
//! that. A tenant found in `policies` but whose model isn't permitted
//! (`ModelAccess::Only` with no matching pattern) is the fourth and most
//! ordinary denial and shares the same treatment.
//!
//! # Config: a vendored proto, same reasoning as `auth.proto`
//!
//! `llmproxy.filters.v0.ModelAuthz`
//! (`proxy-api/vendor/llmproxy/filters/v0/model_authz.proto`) is vendored for
//! its own sake rather than borrowing an unrelated Envoy message -- see that
//! proto's header comment.

use std::collections::HashMap;
use std::sync::Arc;

use http::StatusCode;
use prost_reflect::DynamicMessage;

use proxy_config::ConfigError;
use proxy_http::filter::{
    DecoderCallbacks, FactoryContext, FilterHeadersStatus, FilterInstanceFactory, HttpFilter,
    HttpFilterFactory, RequestHeaders,
};

use crate::auth::TenantPolicy;
use crate::model_authz::{ModelAccess, ModelPattern, TenantPolicyMap};

/// Type URL this filter is registered under.
pub const TYPE_URL: &str = "type.llmproxy.dev/llmproxy.filters.v0.ModelAuthz";

/// The single `%RESPONSE_CODE_DETAILS%` value for every denial this filter
/// issues -- see the module doc's "Fail closed" section for why all four
/// reasons collapse into one generic string rather than distinguishing them.
const DENY_DETAILS: &str = "model_not_permitted";

fn invalid(field_path: impl Into<String>, reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidValue {
        field_path: field_path.into(),
        reason: reason.into(),
    }
}

/// Validates one configured pattern string: non-empty, and a `*` (if any)
/// appears exactly once and only as the final character. See the proto's
/// `OnlyModels.patterns` doc and `crate::model_authz`'s module doc for the
/// matching rule this enforces.
fn validate_pattern(raw: &str, field_path: &str) -> Result<(), ConfigError> {
    if raw.is_empty() {
        return Err(invalid(field_path, "must not be empty"));
    }
    let star_count = raw.matches('*').count();
    if star_count > 1 {
        return Err(invalid(
            field_path,
            "must contain at most one `*` (no regex/glob syntax beyond a single trailing `*`)",
        ));
    }
    if star_count == 1 && !raw.ends_with('*') {
        return Err(invalid(
            field_path,
            "a `*` is only supported as a trailing glob, e.g. `gpt-4*`",
        ));
    }
    Ok(())
}

/// Reads one `TenantModelPolicy.access` oneof into a [`ModelAccess`]. Strict
/// mode: an unset oneof (neither `all` nor `only` present) is a config error
/// naming its own dotted path -- ground rule #1 applies to a oneof exactly
/// as it does to any other field, and this is also the exact case the design
/// brief warns about: the ONLY thing this function must never do on a
/// malformed/unset `access` is return `Ok(ModelAccess::All)`, because that
/// would silently turn "the operator's policy failed to load" into "grant
/// everything", the privilege escalation `TenantPolicy`'s doc names by name.
fn parse_model_access(
    msg: &DynamicMessage,
    policy_index: usize,
) -> Result<ModelAccess, ConfigError> {
    let has_all = msg.has_field_by_name("all");
    let has_only = msg.has_field_by_name("only");

    match (has_all, has_only) {
        (true, false) => Ok(ModelAccess::All),
        (false, true) => {
            let only = msg
                .get_field_by_name("only")
                .and_then(|v| v.as_message().cloned())
                .ok_or_else(|| {
                    invalid(
                        format!("typed_config.policies[{policy_index}].only"),
                        "must be a message",
                    )
                })?;
            let raw_patterns: Vec<prost_reflect::Value> = only
                .get_field_by_name("patterns")
                .and_then(|v| v.as_list().map(<[_]>::to_vec))
                .unwrap_or_default();

            // Empty is legal here -- see `OnlyModels.patterns`'s doc: it
            // denies every model for this tenant, a real policy, not an
            // error.
            let mut patterns = Vec::with_capacity(raw_patterns.len());
            for (j, p) in raw_patterns.iter().enumerate() {
                let field_path =
                    format!("typed_config.policies[{policy_index}].only.patterns[{j}]");
                let raw = p.as_str().unwrap_or_default();
                validate_pattern(raw, &field_path)?;
                patterns.push(ModelPattern::new(raw));
            }
            Ok(ModelAccess::Only(patterns))
        }
        (false, false) => Err(invalid(
            format!("typed_config.policies[{policy_index}].access"),
            "exactly one of `all`/`only` must be set",
        )),
        // A proto3 oneof cannot have two branches set simultaneously through
        // the reflection API used to build this message (setting one clears
        // the other) -- this arm is unreachable in practice, but per ground
        // rule #1's "error, never silently pick one" convention (see
        // `convert_access_log`'s identical treatment of a deprecated oneof
        // member in `proxy-config/src/lower.rs`), it is a loud error rather
        // than a panic or an arbitrary pick.
        (true, true) => Err(invalid(
            format!("typed_config.policies[{policy_index}].access"),
            "both `all` and `only` are set, which a valid oneof cannot produce",
        )),
    }
}

/// Reads `typed_config` (an `llmproxy.filters.v0.ModelAuthz`) into the
/// tenant -> policy map this filter enforces against. Strict mode: every
/// field either maps in or errors with its dotted path (ground rule #1).
///
/// # Absence vs. failure, restated for this function specifically
///
/// An ABSENT `typed_config.policies` list (or an explicitly empty one)
/// parses successfully into an EMPTY [`TenantPolicyMap`] -- exactly like
/// `auth_filter::parse_config`'s empty `virtual_keys` list, which
/// authenticates nothing and therefore refuses everything. A malformed
/// ENTRY inside `policies` (empty tenant, duplicate tenant, unset `access`
/// oneof, a bad pattern) is a hard `Err` naming its own dotted path -- see
/// the "no policy configured" vs. "a policy that failed to load" distinction
/// on `crate::auth::TenantPolicy`'s doc, which this function is the one
/// place responsible for keeping distinct.
pub fn parse_config(config: &DynamicMessage) -> Result<TenantPolicyMap, ConfigError> {
    let mut map: TenantPolicyMap = HashMap::new();
    // Rust note: remembers which earlier index first used a given tenant, so
    // the duplicate error can name the SECOND (offending) index -- same
    // pattern as `auth_filter::parse_config`'s `seen_key_ids`.
    let mut seen: HashMap<String, usize> = HashMap::new();

    let policies: Vec<prost_reflect::Value> = config
        .get_field_by_name("policies")
        .and_then(|v| v.as_list().map(<[_]>::to_vec))
        .unwrap_or_default();

    for (i, entry) in policies.iter().enumerate() {
        let msg = entry
            .as_message()
            .ok_or_else(|| invalid(format!("typed_config.policies[{i}]"), "must be a message"))?;

        let tenant = msg
            .get_field_by_name("tenant")
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        if tenant.is_empty() {
            return Err(invalid(
                format!("typed_config.policies[{i}].tenant"),
                "must not be empty",
            ));
        }
        if let Some(&first) = seen.get(&tenant) {
            return Err(invalid(
                format!("typed_config.policies[{i}].tenant"),
                format!("duplicate `tenant`; already configured at index {first}"),
            ));
        }

        let model_access = parse_model_access(msg, i)?;

        seen.insert(tenant.clone(), i);
        map.insert(tenant, Arc::new(TenantPolicy { model_access }));
    }

    Ok(map)
}

/// [`HttpFilterFactory`] for [`TYPE_URL`]. No `parse_per_route` override --
/// this increment has no per-route config; the trait default
/// (`ConfigError::Unimplemented`) is correct.
#[derive(Default)]
pub struct ModelAuthzFilterFactory;

impl HttpFilterFactory for ModelAuthzFilterFactory {
    fn type_url(&self) -> &'static str {
        TYPE_URL
    }

    fn create(
        &self,
        config: &DynamicMessage,
        _ctx: &FactoryContext,
    ) -> Result<Box<dyn FilterInstanceFactory>, ConfigError> {
        let policies = Arc::new(parse_config(config)?);
        Ok(Box::new(ModelAuthzInstanceFactory { policies }))
    }
}

struct ModelAuthzInstanceFactory {
    /// One map per (filter config, listener), shared by every per-stream
    /// instance below via `Arc::clone` -- same lifetime/reasoning as
    /// `token_limit_filter`'s `Arc<dyn BudgetStore>` and `auth_filter`'s
    /// `Arc<AuthenticatorChain>`.
    policies: Arc<TenantPolicyMap>,
}

impl FilterInstanceFactory for ModelAuthzInstanceFactory {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(ModelAuthzFilterInstance {
            policies: Arc::clone(&self.policies),
        })
    }
}

/// Per-stream instance. Holds only the shared policy map -- there is no
/// per-request state to carry between callbacks (this filter has no
/// encode-side half, like `auth_filter`).
struct ModelAuthzFilterInstance {
    policies: Arc<TenantPolicyMap>,
}

impl ModelAuthzFilterInstance {
    /// The single call site for this filter's 403 -- see the module doc's
    /// "Fail closed" section for why every denial reason shares one generic
    /// wire response and detail string. No `modify_headers` closure (unlike
    /// `auth_filter`'s `www-authenticate` challenge): a 403 has no equivalent
    /// mandatory header.
    fn deny(&self, cb: &mut dyn DecoderCallbacks) {
        cb.send_local_reply(StatusCode::FORBIDDEN, "forbidden", None, DENY_DETAILS);
    }
}

impl HttpFilter for ModelAuthzFilterInstance {
    fn decode_headers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        _headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        // Rust note: `stream_info()` hands back a `RefMut` guard that must
        // not be held across another call on `cb` (see its doc) -- cloning
        // both `Option<String>`s out and letting the guard drop at the end
        // of this block keeps that rule visibly satisfied, same pattern as
        // `token_limit_filter::decode_headers`.
        let (tenant, model) = {
            let info = cb.stream_info();
            (info.auth.tenant.clone(), info.requested_model.clone())
        };

        // Case 1: no authenticated tenant -- see the module doc.
        let Some(tenant) = tenant else {
            self.deny(cb);
            return FilterHeadersStatus::Continue;
        };

        // Case 2: no requested model -- see the module doc.
        let Some(model) = model else {
            self.deny(cb);
            return FilterHeadersStatus::Continue;
        };

        // Case 3 (tenant absent from `self.policies`) and case 4 (tenant
        // present but the model doesn't match its policy) both fall out of
        // this one lookup+check -- see the module doc for why they share the
        // same generic denial rather than being distinguished on the wire.
        let permitted = self
            .policies
            .get(&tenant)
            .is_some_and(|policy| policy.model_access.permits(&model));

        if !permitted {
            self.deny(cb);
        }
        // Rust note: the returned status is irrelevant on the deny path --
        // `drive_decode` checks `ctx.local_reply.is_some()` right after this
        // callback returns and stops the chain unconditionally when set,
        // regardless of what this function returns (see
        // `auth_filter`/`token_limit_filter`'s identical Rust note and
        // `filter_manager.rs`). `Continue` is returned either way only
        // because the trait requires *a* value.
        FilterHeadersStatus::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::{RefCell, RefMut};

    use bytes::Bytes;
    use http::{HeaderMap, Method, StatusCode as HttpStatusCode, Uri};
    use proxy_config::ir::RouteEntry;
    use proxy_http::filter::{BufferedBody, EncoderCallbacks, HeaderMutationFn, PerRouteConfig};
    use proxy_http::stream_info::StreamInfo;

    // --- config-message scaffolding ------------------------------------------

    fn model_authz_desc() -> prost_reflect::MessageDescriptor {
        proxy_api::descriptor_pool()
            .get_message_by_name("llmproxy.filters.v0.ModelAuthz")
            .expect("ModelAuthz is compiled into proxy-api")
    }

    fn tenant_model_policy_desc() -> prost_reflect::MessageDescriptor {
        proxy_api::descriptor_pool()
            .get_message_by_name("llmproxy.filters.v0.TenantModelPolicy")
            .expect("TenantModelPolicy is compiled into proxy-api")
    }

    fn all_models_desc() -> prost_reflect::MessageDescriptor {
        proxy_api::descriptor_pool()
            .get_message_by_name("llmproxy.filters.v0.AllModels")
            .expect("AllModels is compiled into proxy-api")
    }

    fn only_models_desc() -> prost_reflect::MessageDescriptor {
        proxy_api::descriptor_pool()
            .get_message_by_name("llmproxy.filters.v0.OnlyModels")
            .expect("OnlyModels is compiled into proxy-api")
    }

    fn policy_all(tenant: &str) -> DynamicMessage {
        let mut msg = DynamicMessage::new(tenant_model_policy_desc());
        msg.set_field_by_name("tenant", prost_reflect::Value::String(tenant.to_string()));
        msg.set_field_by_name(
            "all",
            prost_reflect::Value::Message(DynamicMessage::new(all_models_desc())),
        );
        msg
    }

    fn policy_only(tenant: &str, patterns: &[&str]) -> DynamicMessage {
        let mut only = DynamicMessage::new(only_models_desc());
        only.set_field_by_name(
            "patterns",
            prost_reflect::Value::List(
                patterns
                    .iter()
                    .map(|p| prost_reflect::Value::String(p.to_string()))
                    .collect(),
            ),
        );
        let mut msg = DynamicMessage::new(tenant_model_policy_desc());
        msg.set_field_by_name("tenant", prost_reflect::Value::String(tenant.to_string()));
        msg.set_field_by_name("only", prost_reflect::Value::Message(only));
        msg
    }

    fn model_authz(policies: Vec<DynamicMessage>) -> DynamicMessage {
        let mut msg = DynamicMessage::new(model_authz_desc());
        msg.set_field_by_name(
            "policies",
            prost_reflect::Value::List(
                policies
                    .into_iter()
                    .map(prost_reflect::Value::Message)
                    .collect(),
            ),
        );
        msg
    }

    // --- descriptor pool ------------------------------------------------------

    #[test]
    fn model_authz_resolves_in_the_descriptor_pool() {
        // Pins the type-URL choice: see `auth_filter`'s equivalent test for
        // why this matters (an unresolvable message fails every bootstrap
        // using this filter with an opaque `UnknownTypeUrl`, not here where
        // the reason is obvious).
        let resolved =
            proxy_api::descriptor_pool().get_message_by_name("llmproxy.filters.v0.ModelAuthz");
        assert!(resolved.is_some(), "{TYPE_URL} must resolve");
    }

    // --- config parsing ---------------------------------------------------------

    #[test]
    fn a_valid_config_parses_all_and_only_policies() {
        let config = model_authz(vec![
            policy_all("tenant-a"),
            policy_only("tenant-b", &["gpt-4*"]),
        ]);
        let map = parse_config(&config).expect("valid config must parse");

        assert_eq!(map.len(), 2);
        assert_eq!(map["tenant-a"].model_access, ModelAccess::All);
        assert_eq!(
            map["tenant-b"].model_access,
            ModelAccess::Only(vec![ModelPattern::new("gpt-4*")])
        );
    }

    #[test]
    fn absent_policies_parses_to_an_empty_map() {
        let config = DynamicMessage::new(model_authz_desc());
        let map = parse_config(&config).expect("absent policies is legal");
        assert!(map.is_empty());
    }

    #[test]
    fn empty_tenant_is_rejected_with_its_field_path() {
        let mut msg = DynamicMessage::new(tenant_model_policy_desc());
        msg.set_field_by_name(
            "all",
            prost_reflect::Value::Message(DynamicMessage::new(all_models_desc())),
        );
        let config = model_authz(vec![msg]);
        let err = parse_config(&config).expect_err("empty tenant must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.policies[0].tenant");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_tenant_is_rejected_naming_index_1() {
        let config = model_authz(vec![policy_all("tenant-a"), policy_all("tenant-a")]);
        let err = parse_config(&config).expect_err("duplicate tenant must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, reason } => {
                assert_eq!(field_path, "typed_config.policies[1].tenant");
                assert!(reason.contains("index 0"));
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    /// THE malformed-policy acceptance case: an unset `access` oneof must
    /// fail config load with its dotted path -- never silently parse as
    /// `ModelAccess::All`.
    #[test]
    fn an_unset_access_oneof_fails_config_load_with_its_dotted_path() {
        let mut msg = DynamicMessage::new(tenant_model_policy_desc());
        msg.set_field_by_name(
            "tenant",
            prost_reflect::Value::String("tenant-a".to_string()),
        );
        let config = model_authz(vec![msg]);
        let err = parse_config(&config).expect_err("an unset access oneof must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, reason } => {
                assert_eq!(field_path, "typed_config.policies[0].access");
                assert!(reason.contains("all") && reason.contains("only"));
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_pattern_is_rejected_with_its_field_path() {
        let config = model_authz(vec![policy_only("tenant-a", &[""])]);
        let err = parse_config(&config).expect_err("an empty pattern must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.policies[0].only.patterns[0]");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn a_non_trailing_star_is_rejected() {
        let config = model_authz(vec![policy_only("tenant-a", &["gpt-*-4"])]);
        let err = parse_config(&config).expect_err("a non-trailing `*` must be rejected");
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn more_than_one_star_is_rejected() {
        let config = model_authz(vec![policy_only("tenant-a", &["gpt-4**"])]);
        let err = parse_config(&config).expect_err("more than one `*` must be rejected");
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn only_with_an_empty_pattern_list_parses_as_deny_all() {
        let config = model_authz(vec![policy_only("tenant-a", &[])]);
        let map = parse_config(&config).expect("an empty patterns list is legal");
        assert_eq!(map["tenant-a"].model_access, ModelAccess::Only(vec![]));
    }

    // --- test scaffolding for filter-behaviour tests ---------------------------

    fn route_named(name: &str) -> Arc<RouteEntry> {
        Arc::new(RouteEntry {
            name: Some(name.to_string()),
            matcher: proxy_config::ir::RouteMatcher {
                path: proxy_config::ir::PathMatch::Prefix("/".to_string()),
                case_sensitive: true,
                headers: vec![],
            },
            action: proxy_config::ir::RouteActionIR::DirectResponse {
                status: 200,
                body: None,
            },
            request_headers_to_add: vec![],
            typed_per_filter_config: Default::default(),
            route_index: 0,
            include_request_attempt_count: false,
            include_attempt_count_in_response: false,
        })
    }

    struct LocalReply {
        status: HttpStatusCode,
        details: String,
    }

    /// A `DecoderCallbacks` + `EncoderCallbacks` double, following
    /// `auth_filter`'s `TestCallbacks` (duplicated deliberately, not shared --
    /// see this crate's convention). Every method this filter doesn't use
    /// panics loudly.
    struct TestCallbacks {
        route: Option<Arc<RouteEntry>>,
        stream_info: RefCell<StreamInfo>,
        local_reply: Option<LocalReply>,
    }

    impl TestCallbacks {
        fn new(route: Option<Arc<RouteEntry>>) -> Self {
            TestCallbacks {
                route,
                stream_info: RefCell::new(StreamInfo::default()),
                local_reply: None,
            }
        }

        fn set_tenant(&self, tenant: &str) {
            self.stream_info.borrow_mut().auth.tenant = Some(tenant.to_string());
        }

        fn set_requested_model(&self, model: &str) {
            self.stream_info.borrow_mut().requested_model = Some(model.to_string());
        }
    }

    impl DecoderCallbacks for TestCallbacks {
        fn send_local_reply(
            &mut self,
            code: HttpStatusCode,
            _body: &str,
            modify_headers: Option<HeaderMutationFn>,
            details: &str,
        ) {
            assert!(
                modify_headers.is_none(),
                "model_authz_filter's 403 carries no header mutation"
            );
            self.local_reply = Some(LocalReply {
                status: code,
                details: details.to_string(),
            });
        }
        fn continue_decoding(&mut self) {
            unimplemented!("model_authz_filter never stops iteration")
        }
        fn add_decoded_data(&mut self, _data: Bytes, _streaming: bool) {
            unimplemented!("model_authz_filter never buffers request data")
        }
        fn inject_decoded_data_to_filter_chain(&mut self, _data: Bytes, _end_stream: bool) {
            unimplemented!("model_authz_filter never injects data")
        }
        fn decoding_buffer(&self) -> Option<&BufferedBody> {
            unimplemented!("model_authz_filter never consults the decoding buffer")
        }
        fn modify_decoding_buffer(&mut self, _f: &mut dyn FnMut(&mut bytes::BytesMut)) {
            unimplemented!("model_authz_filter never touches request bytes")
        }
        fn route(&mut self) -> Option<Arc<RouteEntry>> {
            self.route.clone()
        }
        fn clear_route_cache(&mut self) {
            unimplemented!("model_authz_filter never rewrites routing headers")
        }
        fn per_route_config(&mut self) -> Option<Arc<dyn PerRouteConfig>> {
            None
        }
        fn stream_info(&mut self) -> RefMut<'_, StreamInfo> {
            self.stream_info.borrow_mut()
        }
    }

    impl EncoderCallbacks for TestCallbacks {
        fn continue_encoding(&mut self) {
            unimplemented!("model_authz_filter has no encode-side callbacks")
        }
        fn add_encoded_data(&mut self, _data: Bytes, _streaming: bool) {
            unimplemented!("model_authz_filter has no encode-side callbacks")
        }
        fn inject_encoded_data_to_filter_chain(&mut self, _data: Bytes, _end_stream: bool) {
            unimplemented!("model_authz_filter has no encode-side callbacks")
        }
        fn encoding_buffer(&self) -> Option<&BufferedBody> {
            unimplemented!("model_authz_filter has no encode-side callbacks")
        }
        fn modify_encoding_buffer(&mut self, _f: &mut dyn FnMut(&mut bytes::BytesMut)) {
            unimplemented!("model_authz_filter has no encode-side callbacks")
        }
        fn stream_info(&mut self) -> RefMut<'_, StreamInfo> {
            self.stream_info.borrow_mut()
        }
    }

    fn request_headers() -> RequestHeaders {
        RequestHeaders {
            method: Method::POST,
            uri: Uri::from_static("/v1/chat/completions"),
            headers: HeaderMap::new(),
        }
    }

    fn filter_with(policies: TenantPolicyMap) -> ModelAuthzFilterInstance {
        ModelAuthzFilterInstance {
            policies: Arc::new(policies),
        }
    }

    fn policies_map(entries: Vec<(&str, ModelAccess)>) -> TenantPolicyMap {
        entries
            .into_iter()
            .map(|(tenant, model_access)| {
                (tenant.to_string(), Arc::new(TenantPolicy { model_access }))
            })
            .collect()
    }

    // --- acceptance: Only([gpt-4*]) -----------------------------------------

    #[test]
    fn a_tenant_with_only_gpt4_glob_is_allowed_gpt4o_and_denied_claude3() {
        let policies = policies_map(vec![(
            "tenant-a",
            ModelAccess::Only(vec![ModelPattern::new("gpt-4*")]),
        )]);

        // gpt-4o: 200 (Continue, no local reply).
        let mut filter = filter_with(policies.clone());
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        cb.set_tenant("tenant-a");
        cb.set_requested_model("gpt-4o");
        let mut head = request_headers();
        let status = filter.decode_headers(&mut cb, &mut head, true);
        assert_eq!(status, FilterHeadersStatus::Continue);
        assert!(cb.local_reply.is_none(), "gpt-4o must be permitted");

        // claude-3: 403.
        let mut filter = filter_with(policies);
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        cb.set_tenant("tenant-a");
        cb.set_requested_model("claude-3");
        let mut head = request_headers();
        filter.decode_headers(&mut cb, &mut head, true);
        let reply = cb.local_reply.expect("claude-3 must be denied");
        assert_eq!(reply.status, HttpStatusCode::FORBIDDEN);
        assert_eq!(reply.details, "model_not_permitted");
    }

    // --- acceptance: All / no policy -----------------------------------------

    #[test]
    fn a_tenant_with_all_access_permits_any_model() {
        let policies = policies_map(vec![("tenant-a", ModelAccess::All)]);
        let mut filter = filter_with(policies);
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        cb.set_tenant("tenant-a");
        cb.set_requested_model("some-completely-unlisted-model");
        let mut head = request_headers();
        filter.decode_headers(&mut cb, &mut head, true);
        assert!(cb.local_reply.is_none());
    }

    // --- acceptance: unauthenticated request -> 403, never implicitly allowed --

    #[test]
    fn no_authenticated_tenant_is_refused_not_implicitly_allowed() {
        let policies = policies_map(vec![("tenant-a", ModelAccess::All)]);
        let mut filter = filter_with(policies);
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        // No `set_tenant` call -- StreamInfo::auth.tenant stays None.
        cb.set_requested_model("gpt-4o");
        let mut head = request_headers();
        filter.decode_headers(&mut cb, &mut head, true);
        let reply = cb
            .local_reply
            .expect("an unauthenticated stream must be refused, not implicitly allowed");
        assert_eq!(reply.status, HttpStatusCode::FORBIDDEN);
        assert_eq!(reply.details, "model_not_permitted");
    }

    // --- acceptance: no requested model -> 403 -------------------------------

    #[test]
    fn no_requested_model_is_refused() {
        let policies = policies_map(vec![("tenant-a", ModelAccess::All)]);
        let mut filter = filter_with(policies);
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        cb.set_tenant("tenant-a");
        // No `set_requested_model` call -- StreamInfo::requested_model stays None.
        let mut head = request_headers();
        filter.decode_headers(&mut cb, &mut head, true);
        let reply = cb
            .local_reply
            .expect("a request with no extractable model must be refused");
        assert_eq!(reply.status, HttpStatusCode::FORBIDDEN);
    }

    // --- an authenticated tenant absent from a CONFIGURED map is refused ------

    #[test]
    fn a_tenant_absent_from_a_configured_map_is_refused_not_implicitly_allowed() {
        let policies = policies_map(vec![("tenant-a", ModelAccess::All)]);
        let mut filter = filter_with(policies);
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        cb.set_tenant("tenant-unknown-to-this-config");
        cb.set_requested_model("gpt-4o");
        let mut head = request_headers();
        filter.decode_headers(&mut cb, &mut head, true);
        let reply = cb.local_reply.expect(
            "a tenant absent from a configured policy map must be refused, per the design \
             brief's config/consistency rule -- it must never be treated as an implicit allow",
        );
        assert_eq!(reply.status, HttpStatusCode::FORBIDDEN);
    }
}
