//! Wires [`crate::model_authz`]'s `ModelAccess`/
//! `ModelPattern` matcher into a real decode-path `HttpFilter`:
//! `llmproxy.model_authz`.
//!
//! # Decode-path only, and it must run LAST among the LLM-layer filters it needs
//!
//! This filter needs two facts that only exist once two OTHER decode-path
//! filters have already run: `StreamInfo::auth.tenant` (written by
//! `llmproxy.auth`) and `StreamInfo::requested_model` (written by
//! `llmproxy.body_rewrite`). Both of those filters must be configured
//! BEFORE `llmproxy.model_authz` in a listener's `http_filters` list;
//! `proxy_config::lower::check_lane_h_filter_order` rejects the wrong order
//! at config load, with an error explaining why -- see that function's doc.
//!
//! **Config order is necessary but NOT sufficient, and assuming otherwise
//! was a P0 (found 2026-09-04, fixed the same day).** The two facts arrive
//! in DIFFERENT phases, not merely at different chain positions:
//!
//! - `auth` writes `auth.tenant` from its `decode_headers`;
//! - `body_rewrite` writes `requested_model` from its `decode_data`.
//!
//! `filter_manager::drive_decode` runs EVERY filter's `decode_headers`
//! first, and only then delivers data in a trailing loop over
//! `[0, header_reach)`. So a header-phase read of `requested_model` sees
//! `None` no matter how the chain is ordered -- and this filter, which did
//! exactly that, denied 100% of traffic in any chain that enabled it. Its
//! own unit tests all passed, because they wrote the field directly and
//! called `decode_headers` themselves, never going through `drive_decode`.
//!
//! The split below follows the phases rather than fighting them: the tenant
//! check stays in `decode_headers` (where the fact genuinely is available),
//! and the model check runs from `decode_data`/`decode_trailers`, where
//! config order DOES hold because that trailing loop is itself in config
//! order. See [`ModelAuthzFilterInstance::authorize_model`].
//!
//! Get the config order backwards and this filter reads `None` for the
//! tenant and refuses EVERY request (see the next section), which is at
//! least loud, unlike the two existing LLM-layer ordering traps this one joins
//! (`token_limit_filter`'s module doc).
//!
//! # Fail closed on missing inputs; OPEN on an unconfigured tenant
//!
//! Two ways this filter refuses a request, both with the SAME wire response
//! and the SAME generic `%RESPONSE_CODE_DETAILS%` (`model_not_permitted` --
//! never naming which applied, and never rendering a policy's contents or a
//! tenant's allow-list):
//!
//! 1. **No authenticated tenant** (`StreamInfo::auth.tenant` is `None`) -- an
//!    unauthenticated stream cannot be authorized against a per-tenant
//!    policy. This is the authentic**ation** axis (fails closed, always),
//!    not the authoriz**ation** axis below -- see
//!    `crate::auth::TenantPolicy`'s doc for why the two must not be confused.
//! 2. **No requested model** (`StreamInfo::requested_model` is `None`) -- a
//!    body with no extractable `model` cannot be checked against a model
//!    allow-list.
//!
//! A tenant found in the snapshot's `policies` but whose model isn't
//! permitted (`ModelAccess::Only` with no matching pattern) is a third,
//! ordinary denial sharing the same treatment.
//!
//! **An authenticated tenant ABSENT from the snapshot's `policies` is
//! ALLOWED**, not refused -- this reverses the filter's
//! original behavior (refuse), an owner decision. Authorization
//! defaults OPEN (`ModelAccess::default()` is `All`; see
//! `crate::model_authz::ModelAccess`'s doc), and that
//! default applies uniformly whether the tenant is missing because this
//! filter is absent from the chain OR because it is present but nothing
//! ever wrote a policy for that tenant -- the two are no longer
//! distinguished. The accepted consequence: an operator who configures
//! policies for tenants A and B and forgets C grants C full access rather
//! than refusing it. If that surprises an operator, the fix is a policy
//! (`Only(vec![])` denies every model for a tenant), not a filter behavior
//! change here.
//!
//! # Config: a vendored proto, same reasoning as `auth.proto`
//!
//! `llmproxy.filters.v0.ModelAuthz`
//! (`proxy-api/vendor/llmproxy/filters/v0/model_authz.proto`) is vendored for
//! its own sake rather than borrowing an unrelated Envoy message -- see that
//! proto's header comment.
//!
//! # Reads the `ControlPlaneSnapshot`, not its own `typed_config`
//!
//! This filter does not enforce the policy
//! map `typed_config.policies` parses to directly. Instead
//! [`ModelAuthzFilterFactory::create`] resolves the SAME
//! `crate::control::ControlPlane` singleton `llmproxy.auth`'s factory
//! registers (`ctx.get(auth_filter::TYPE_URL)`, which resolves through this
//! chain's own `FactoryContext::scope` -- see `SharedFactoryState`'s doc for
//! why that matters -- never `get_or_try_init`: this filter has none of the inputs (HMAC secret,
//! bootstrap keys, store selection) a fresh `ControlPlane` would need, and
//! must not invent them), seeds `typed_config.policies` into it as
//! BOOTSTRAP data (`ControlPlane::seed_bootstrap_policies`), and holds the
//! published `Arc<ArcSwap<ControlPlaneSnapshot>>` for the request-time
//! lookup below. This is what makes admin `PUT /tenants/{id}/policy`
//! (which writes to the SAME `ControlPlane` and republishes) take effect on
//! this filter's very next request, with no reload -- an admin endpoint with its own
//! store would have had no path to this filter at all.
//!
//! `proxy_config`'s lowering requires `llmproxy.auth` BEFORE
//! `llmproxy.model_authz` in a listener's `http_filters` list (the same
//! ordering this module's "Decode-path only" section above already
//! required for `StreamInfo::auth.tenant`/`requested_model`), so by the
//! time this filter's `create` runs, `llmproxy.auth`'s factory has already
//! registered the singleton earlier in the SAME per-worker build. `None`
//! here is therefore always a config error, not a race: `model_authz`
//! configured without `llmproxy.auth` anywhere in the chain. That combination used to be legal and silently denied every request
//! (case 1 above, no tenant ever gets set); an explicit load-time error is
//! strictly better and is what AGENTS.md invariant 1 asks for.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use http::StatusCode;
use prost_reflect::DynamicMessage;

use bytes::Bytes;
use proxy_config::ConfigError;
use proxy_http::filter::{
    DecoderCallbacks, FactoryContext, FilterDataStatus, FilterHeadersStatus, FilterInstanceFactory,
    FilterTrailersStatus, HttpFilter, HttpFilterFactory, RequestHeaders, RequestTrailers,
};

use crate::auth::TenantPolicy;
use crate::auth_filter;
use crate::control::{ControlPlane, ControlPlaneSnapshot};
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
/// naming its own dotted path -- AGENTS.md invariant 1 applies to a oneof exactly
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
        // the other) -- this arm is unreachable in practice, but per
        // AGENTS.md invariant 1's "error, never silently pick one" convention (see
        // `convert_access_log`'s identical treatment of a deprecated oneof
        // member in `proxy-config/src/lower.rs`), it is a loud error rather
        // than a panic or an arbitrary pick.
        (true, true) => Err(invalid(
            format!("typed_config.policies[{policy_index}].access"),
            "both `all` and `only` are set, which a valid oneof cannot produce",
        )),
    }
}

/// Reads `typed_config` (an `llmproxy.filters.v0.ModelAuthz`) into a
/// tenant -> policy map. This is BOOTSTRAP data
/// -- [`ModelAuthzFilterFactory::create`] passes the result to
/// `ControlPlane::seed_bootstrap_policies`, not to this filter's own
/// enforcement path, which reads the published `ControlPlaneSnapshot`
/// instead (see the module doc). Strict mode still applies exactly as
/// before: every field either maps in or errors with its dotted path
/// (AGENTS.md invariant 1).
///
/// # Absence vs. failure, restated for this function specifically
///
/// An ABSENT `typed_config.policies` list (or an explicitly empty one)
/// parses successfully into an EMPTY [`TenantPolicyMap`] -- exactly like
/// `auth_filter::parse_config`'s empty `virtual_keys` list. Nothing to seed
/// is legal; it leaves the store's own policies (if any) as the only
/// source. A malformed ENTRY inside `policies` (empty tenant, duplicate
/// tenant, unset `access` oneof, a bad pattern) is a hard `Err` naming its
/// own dotted path -- see the "no policy configured" vs. "a policy that
/// failed to load" distinction on `crate::auth::TenantPolicy`'s doc, which
/// this function is the one place responsible for keeping distinct.
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

        let allow = parse_model_access(msg, i)?;
        let deny = msg
            .get_field_by_name("deny_patterns")
            .and_then(|v| v.as_list().map(<[_]>::to_vec))
            .unwrap_or_default()
            .into_iter()
            .enumerate()
            .map(|(j, value)| {
                let path = format!("typed_config.policies[{i}].deny_patterns[{j}]");
                let pattern = value
                    .as_str()
                    .ok_or_else(|| invalid(&path, "must be a string"))?;
                validate_pattern(pattern, &path)?;
                Ok(ModelPattern::new(pattern))
            })
            .collect::<Result<Vec<_>, ConfigError>>()?;
        let model_access = allow.with_deny(deny);

        seen.insert(tenant.clone(), i);
        map.insert(
            tenant,
            Arc::new(TenantPolicy {
                model_access,
                budget: None,
            }),
        );
    }

    Ok(map)
}

/// [`HttpFilterFactory`] for [`TYPE_URL`]. No `parse_per_route` override --
/// this filter has no per-route config; the trait default
/// (`ConfigError::Unimplemented`) is correct.
#[derive(Default)]
pub struct ModelAuthzFilterFactory;

impl HttpFilterFactory for ModelAuthzFilterFactory {
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
        let policies = parse_config(config)?;

        // Resolve the SAME `ControlPlane` singleton
        // `llmproxy.auth`'s factory registers -- see the module doc's "Reads
        // the ControlPlaneSnapshot" section for why this is `ctx.get` (never
        // `get_or_try_init`: this filter has none of a fresh `ControlPlane`'s
        // required inputs and must not invent them) and why `None` is always
        // a config error rather than a race, given `proxy_config`'s
        // lowering-enforced filter order. `ctx.get` resolves through THIS
        // chain's own `scope` -- since `llmproxy.auth` and `llmproxy.model_authz`
        // are always in the same chain (the ordering rule above), they share
        // one `FactoryContext::scope` and so see the same singleton.
        let control_plane = ctx
            .get(auth_filter::TYPE_URL)
            .ok_or_else(|| {
                invalid(
                    "typed_config",
                    "llmproxy.model_authz requires llmproxy.auth earlier in the same \
                     filter chain -- its ControlPlane singleton is where this filter's \
                     tenant policies live",
                )
            })?
            .downcast::<ControlPlane>()
            .expect(
                "the control-plane singleton registered under auth_filter::TYPE_URL \
                     is always a ControlPlane",
            );

        // `typed_config.policies` is BOOTSTRAP seed, not the live policy
        // source -- see the module doc. `create` runs once per worker
        // (ADR-0003), so this call happens N times with an identical map;
        // `seed_bootstrap_policies`'s store-wins merge makes every call
        // after the first a no-op (see its doc's "Idempotence" section).
        control_plane
            .seed_bootstrap_policies(&policies)
            .map_err(|e| {
                invalid(
                    "typed_config.policies",
                    format!(
                        "bootstrap policies could not be seeded into the control-plane store: {e}"
                    ),
                )
            })?;

        Ok(Box::new(ModelAuthzInstanceFactory {
            snapshot: control_plane.handle(),
        }))
    }
}

struct ModelAuthzInstanceFactory {
    /// One handle per (filter config, listener), shared by every per-stream
    /// instance below via `Arc::clone` -- same lifetime/reasoning as
    /// `auth_filter`'s `VirtualKeyAuthenticator`, which holds the identical
    /// kind of handle for the identical reason (see `control.rs`'s module
    /// doc).
    snapshot: Arc<ArcSwap<ControlPlaneSnapshot>>,
}

impl FilterInstanceFactory for ModelAuthzInstanceFactory {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(ModelAuthzFilterInstance {
            decided: false,
            snapshot: Arc::clone(&self.snapshot),
        })
    }
}

/// Per-stream instance. Holds only the shared snapshot handle -- there is no
/// per-request state to carry between callbacks (this filter has no
/// encode-side half, like `auth_filter`).
struct ModelAuthzFilterInstance {
    snapshot: Arc<ArcSwap<ControlPlaneSnapshot>>,
    /// Whether the model check has already run for this stream. The check
    /// has three possible trigger points (end-of-body, trailers, or a
    /// bodyless request) and must run exactly once -- see
    /// [`Self::authorize_model`].
    decided: bool,
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

    /// Cases 2 and 3 of the module doc: the checks that need
    /// `StreamInfo::requested_model`, and therefore cannot run before
    /// `llmproxy.body_rewrite`'s `decode_data` has published it.
    ///
    /// **Why this is not in `decode_headers`, which is where it lived until
    /// 2026-09-04 and where it denied every request in a real chain.**
    /// `body_rewrite` writes `requested_model` from its `decode_data`, and
    /// `filter_manager::drive_decode` runs EVERY filter's `decode_headers`
    /// first and only then delivers data in a trailing loop over
    /// `[0, header_reach)`. So a header-phase read of that field is
    /// guaranteed to see `None` no matter how the chain is ordered -- a
    /// header/data PHASE mismatch, not a config-order bug. `decode_data`
    /// is delivered in config order within that trailing loop, so reading
    /// the field here does what the original code intended to do.
    ///
    /// Idempotent via `self.decided`: the trigger points below overlap (a
    /// chunked body ends with `end_stream`, a trailered request never sets
    /// `end_stream` on data at all), and a second call must not send a
    /// second local reply.
    fn authorize_model(&mut self, cb: &mut dyn DecoderCallbacks) {
        if self.decided {
            return;
        }
        self.decided = true;

        // Rust note: same `RefMut`-guard discipline as `decode_headers` --
        // clone out and let the guard drop before any other call on `cb`.
        let (tenant, model) = {
            let info = cb.stream_info();
            (info.auth.tenant.clone(), info.requested_model.clone())
        };

        // Case 1 is re-checked rather than assumed: `decode_headers` already
        // refused a stream with no tenant (and a local reply stops the
        // chain, so this normally cannot be reached), but this function
        // must not silently authorize against a `None` tenant if that ever
        // stops holding.
        let Some(tenant) = tenant else {
            self.deny(cb);
            return;
        };

        // Case 2: no requested model -- see the module doc. This is also
        // the path a bodyless request takes: `decode_data` is still
        // delivered (with an empty `body` and `end_stream`), nothing ever
        // published a model, and the request is refused rather than
        // slipping through unchecked.
        let Some(model) = model else {
            self.deny(cb);
            return;
        };

        // Rust note: `ArcSwap::load` hands back a lock-free guard over
        // whatever `Arc<ControlPlaneSnapshot>` is CURRENTLY published --
        // re-loaded on every call, not cached on `self` -- so a
        // `ControlPlane::set_policy` write (e.g. via the admin `PUT
        // /tenants/{id}/policy` endpoint) republished between two requests
        // on this same filter instance is visible on the very next one, with
        // no reload. See `auth_filter::AuthFilterInstance`'s identical
        // pattern and the module doc's "Reads the ControlPlaneSnapshot"
        // section.
        let snapshot = self.snapshot.load();
        let permitted = match snapshot.policies.get(&tenant) {
            Some(policy) => policy.model_access.permits(&model),
            // No policy configured for this tenant in the published
            // snapshot -- `ModelAccess::default()` is `All`, so this falls
            // out to the OPEN default rather than a denial. XX (see the module doc);
            // the `None` arm is written out explicitly, not folded into
            // `is_some_and`, so which way "absent" falls is visible without
            // reconstructing combinator semantics.
            None => true,
        };

        if !permitted {
            self.deny(cb);
        }
    }
}

impl HttpFilter for ModelAuthzFilterInstance {
    /// Case 1 only: refuse a stream with no authenticated tenant. That fact
    /// IS available here -- `llmproxy.auth` writes `StreamInfo::auth.tenant`
    /// from its own `decode_headers`, and config order (enforced by
    /// `proxy_config::lower::check_lane_h_filter_order`) puts it earlier in
    /// the same header phase.
    ///
    /// The model check deliberately does NOT run here; see
    /// [`ModelAuthzFilterInstance::authorize_model`] for why a header-phase
    /// read of `StreamInfo::requested_model` can only ever see `None`.
    fn decode_headers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        _headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        // Rust note: `stream_info()` hands back a `RefMut` guard that must
        // not be held across another call on `cb` (see its doc) -- cloning
        // out and letting the guard drop at the end of this block keeps that
        // rule visibly satisfied, same pattern as
        // `token_limit_filter::decode_headers`.
        // `decode_headers` is the start of a stream, so this is where the
        // once-per-stream decision latch resets. In production a filter
        // instance already serves exactly one stream (`create` runs per
        // stream), which would make this redundant -- it is here so the
        // latch cannot silently suppress the check if an instance is ever
        // reused, which is precisely what a unit test does when it drives
        // two requests through one instance.
        self.decided = false;

        let tenant = { cb.stream_info().auth.tenant.clone() };

        // Case 1: no authenticated tenant -- see the module doc.
        if tenant.is_none() {
            // Nothing further can authorize this stream, so record the
            // decision here too: `decode_data` must not send a second local
            // reply behind this one.
            self.decided = true;
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

    /// The model check's ordinary trigger point. `end_stream` here means the
    /// full body has been delivered, so `llmproxy.body_rewrite` -- earlier in
    /// this same trailing loop, by config order -- has already published
    /// `StreamInfo::requested_model`.
    ///
    /// A bodyless request still reaches this callback (`filter_manager`
    /// delivers `decode_data` unconditionally to every filter in
    /// `[0, header_reach)`, with an empty buffer), which is what keeps it
    /// from becoming an authorization bypass.
    fn decode_data(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        _data: &mut Bytes,
        end_stream: bool,
    ) -> FilterDataStatus {
        if end_stream {
            self.authorize_model(cb);
        }
        FilterDataStatus::Continue
    }

    /// The trailered-request trigger point. `filter_manager` computes
    /// `end_stream = trailers.is_none()` for `decode_data`, so a request
    /// carrying trailers never sees `end_stream` on data at all -- without
    /// this callback such a request would skip the check entirely, which is
    /// a bypass rather than merely a missed denial.
    fn decode_trailers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        _trailers: &mut RequestTrailers,
    ) -> FilterTrailersStatus {
        self.authorize_model(cb);
        FilterTrailersStatus::Continue
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

    use crate::auth::{HmacSecret, KeySet, TenantId};
    use crate::control::InMemoryControlPlaneStore;

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
    fn deny_patterns_parse_and_override_allow() {
        let mut policy = policy_only("tenant-a", &["gpt-*"]);
        policy.set_field_by_name(
            "deny_patterns",
            prost_reflect::Value::List(vec![prost_reflect::Value::String("gpt-5*".into())]),
        );
        let map = parse_config(&model_authz(vec![policy])).unwrap();
        let access = &map["tenant-a"].model_access;
        assert!(access.permits("gpt-4o"));
        assert!(!access.permits("gpt-5-mini"));
    }

    #[test]
    fn malformed_deny_pattern_reports_its_path() {
        let mut policy = policy_all("tenant-a");
        policy.set_field_by_name(
            "deny_patterns",
            prost_reflect::Value::List(vec![prost_reflect::Value::String("gpt-*-mini".into())]),
        );
        let err = parse_config(&model_authz(vec![policy])).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidValue { field_path, .. } if field_path == "typed_config.policies[0].deny_patterns[0]")
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
            streaming_strict: false,
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

    /// Builds a filter instance over a bare, never-`rebuild`-ed snapshot
    /// carrying exactly `policies` -- the model_authz analogue of
    /// `control::test_snapshot_handle`, which cannot be reused here as-is
    /// because it hard-codes an empty `policies` map (see this crate's
    /// convention of not sharing test scaffolding across files -- the same
    /// one `auth_filter`'s and this file's own `TestCallbacks` follow).
    fn filter_with(policies: TenantPolicyMap) -> ModelAuthzFilterInstance {
        let snapshot = Arc::new(ArcSwap::new(Arc::new(ControlPlaneSnapshot {
            keys: KeySet::new(),
            policies,
            key_budgets: Default::default(),
            key_tenants: Default::default(),
            tenant_credentials: HashMap::new(),
        })));
        ModelAuthzFilterInstance {
            snapshot,
            decided: false,
        }
    }

    fn policies_map(entries: Vec<(&str, ModelAccess)>) -> TenantPolicyMap {
        entries
            .into_iter()
            .map(|(tenant, model_access)| {
                (
                    tenant.to_string(),
                    Arc::new(TenantPolicy {
                        model_access,
                        budget: None,
                    }),
                )
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
        let status = filter.decode_headers(&mut cb, &mut head, false);
        decode_request_after_headers(&mut filter, &mut cb);
        assert_eq!(status, FilterHeadersStatus::Continue);
        assert!(cb.local_reply.is_none(), "gpt-4o must be permitted");

        // claude-3: 403.
        let mut filter = filter_with(policies);
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        cb.set_tenant("tenant-a");
        cb.set_requested_model("claude-3");
        decode_request(&mut filter, &mut cb);
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
        decode_request(&mut filter, &mut cb);
        assert!(cb.local_reply.is_none());
    }

    #[test]
    fn deny_pattern_returns_403_even_when_allow_matches() {
        let access = ModelAccess::Only(vec![ModelPattern::new("gpt-*")])
            .with_deny(vec![ModelPattern::new("gpt-5*")]);
        let policies = policies_map(vec![("tenant-a", access)]);
        let mut filter = filter_with(policies);
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        cb.set_tenant("tenant-a");
        cb.set_requested_model("gpt-5-mini");
        decode_request(&mut filter, &mut cb);
        let reply = cb
            .local_reply
            .expect("denied model must return a local reply");
        assert_eq!(reply.status, HttpStatusCode::FORBIDDEN);
        assert_eq!(reply.details, "model_not_permitted");
    }

    // --- acceptance: unauthenticated request -> 403, never implicitly allowed --

    #[test]
    fn no_authenticated_tenant_is_refused_not_implicitly_allowed() {
        let policies = policies_map(vec![("tenant-a", ModelAccess::All)]);
        let mut filter = filter_with(policies);
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        // No `set_tenant` call -- StreamInfo::auth.tenant stays None.
        cb.set_requested_model("gpt-4o");
        decode_request(&mut filter, &mut cb);
        let reply = cb
            .local_reply
            .expect("an unauthenticated stream must be refused, not implicitly allowed");
        assert_eq!(reply.status, HttpStatusCode::FORBIDDEN);
        assert_eq!(reply.details, "model_not_permitted");
    }

    // --- acceptance: no requested model -> 403 -------------------------------

    /// Companion to [`decode_request`] for the one test that asserts on
    /// `decode_headers`' returned status: it has already run the header
    /// phase itself, so this delivers only the trailing data phase.
    fn decode_request_after_headers(filter: &mut dyn HttpFilter, cb: &mut TestCallbacks) {
        if cb.local_reply.is_some() {
            return;
        }
        let mut body = Bytes::new();
        filter.decode_data(cb, &mut body, true);
    }

    /// Drive the filter the way `filter_manager::drive_decode` actually
    /// does: the ENTIRE header phase first, then the trailing data phase.
    ///
    /// Tests that exercise the model check must go through this rather than
    /// calling `decode_headers` directly. Calling it directly is exactly
    /// what hid the 2026-09-04 P0: 18 unit tests passed while the filter
    /// denied every request in a real chain, because they wrote
    /// `StreamInfo::requested_model` themselves and then invoked the one
    /// callback that, in production, always runs before anything sets it.
    ///
    /// `end_stream: false` on headers mirrors a request that has a body;
    /// the `local_reply` check between the phases is S2.5 (a local reply
    /// stops the chain, so no data is delivered afterwards).
    fn decode_request(filter: &mut dyn HttpFilter, cb: &mut TestCallbacks) {
        let mut head = request_headers();
        filter.decode_headers(cb, &mut head, false);
        if cb.local_reply.is_some() {
            return;
        }
        let mut body = Bytes::new();
        filter.decode_data(cb, &mut body, true);
    }

    #[test]
    fn no_requested_model_is_refused() {
        let policies = policies_map(vec![("tenant-a", ModelAccess::All)]);
        let mut filter = filter_with(policies);
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        cb.set_tenant("tenant-a");
        // No `set_requested_model` call -- StreamInfo::requested_model stays None.
        decode_request(&mut filter, &mut cb);
        let reply = cb
            .local_reply
            .expect("a request with no extractable model must be refused");
        assert_eq!(reply.status, HttpStatusCode::FORBIDDEN);
    }

    // --- an authenticated tenant absent from the snapshot is
    //     ALLOWED -- the reversal of 3a's case 3. Mutation pin 1: flipping
    //     the `None` arm in `decode_headers` to `false` must red this test.

    #[test]
    fn a_tenant_absent_from_the_snapshot_is_allowed() {
        let policies = policies_map(vec![("tenant-a", ModelAccess::All)]);
        let mut filter = filter_with(policies);
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        cb.set_tenant("tenant-unknown-to-this-snapshot");
        cb.set_requested_model("gpt-4o");
        decode_request(&mut filter, &mut cb);
        assert!(
            cb.local_reply.is_none(),
            "a tenant absent from the published snapshot must be ALLOWED -- authorization \
             defaults OPEN, and this reverses the original refuse behavior (see the module \
             doc's \"Fail closed on missing inputs; OPEN on an unconfigured tenant\" section)"
        );
    }

    // --- config load: model_authz with no llmproxy.auth in the chain -------

    #[test]
    fn model_authz_without_auth_in_the_chain_is_a_config_load_error() {
        // No `auth_filter::TYPE_URL` singleton has been registered in this
        // `FactoryContext` -- standing in for a listener that configures
        // `llmproxy.model_authz` without `llmproxy.auth` anywhere earlier in
        // its filter chain.
        let ctx = FactoryContext::default();
        let config = model_authz(vec![]);

        // Rust note: `expect_err` needs `T: Debug`, and `Box<dyn
        // FilterInstanceFactory>` (this call's `Ok` type) isn't -- a plain
        // `match` sidesteps that instead of adding a `Debug` impl nothing
        // else needs.
        let err = match ModelAuthzFilterFactory.create(&config, &ctx) {
            Ok(_) => {
                panic!("model_authz without llmproxy.auth in the chain must be a config error")
            }
            Err(e) => e,
        };
        match err {
            ConfigError::InvalidValue { field_path, reason } => {
                assert_eq!(field_path, "typed_config");
                assert!(
                    reason.contains("llmproxy.auth"),
                    "the error must name the missing filter: {reason}"
                );
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    // --- THE acceptance test: an admin write (`ControlPlane::set_policy`,
    //     exactly what `PUT /tenants/{id}/policy` calls) changes what this
    //     filter enforces on the very next request, with NO reload. Mutation
    //     pin 3: reading a cached `TenantPolicyMap` clone instead of
    //     `self.snapshot.load()` must red this test.

    #[test]
    fn an_admin_write_changes_enforcement_on_the_next_request_with_no_reload() {
        let ctx = FactoryContext::default();
        // Stands in for `auth_filter::AuthFilterFactory::create` having
        // already run earlier in the SAME worker's chain build and
        // registered the `ControlPlane` singleton -- see the module doc's
        // "Reads the ControlPlaneSnapshot" section for why this filter must
        // resolve, not build, that singleton.
        let cp = Arc::new(
            ControlPlane::new(
                Box::new(InMemoryControlPlaneStore::default()),
                HmacSecret::new(b"operator-secret"),
                KeySet::new(),
            )
            .expect("empty store must not fail boot"),
        );
        ctx.get_or_try_init(auth_filter::TYPE_URL, || {
            Ok(Arc::clone(&cp) as Arc<dyn std::any::Any + Send + Sync>)
        })
        .expect("registering the control-plane singleton must succeed");

        // No bootstrap policies configured -- the ONLY policy source in this
        // test is the admin write below.
        let config = model_authz(vec![]);
        let instance_factory = ModelAuthzFilterFactory
            .create(&config, &ctx)
            .expect("valid config with llmproxy.auth already registered must build");
        let mut filter = instance_factory.create_filter();

        // Before any admin write: tenant-a is absent from the snapshot, so
        // it is allowed (the OPEN default).
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        cb.set_tenant("tenant-a");
        cb.set_requested_model("claude-3");
        decode_request(&mut *filter, &mut cb);
        assert!(
            cb.local_reply.is_none(),
            "tenant-a has no policy yet, so it must be allowed"
        );

        // The admin endpoint's exact call.
        cp.set_policy(
            &TenantId::new("tenant-a"),
            &ModelAccess::Only(vec![ModelPattern::new("gpt-4*")]),
        )
        .expect("set_policy must succeed");

        // The SAME filter instance, no reload -- the next request must
        // reflect the write.
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        cb.set_tenant("tenant-a");
        cb.set_requested_model("claude-3");
        decode_request(&mut *filter, &mut cb);
        let reply = cb.local_reply.expect(
            "an admin PUT /tenants/{id}/policy must change enforcement on the very next \
             request, with no reload -- this is the reason the filter reads the snapshot",
        );
        assert_eq!(reply.status, HttpStatusCode::FORBIDDEN);
    }

    // --- 2026-09-04 P0 regression: the header/data PHASE mismatch ---------
    //
    // Found by `testing/diffrig/tests/admin_e2e.rs`, the first drill to run
    // the admin API against the real binary. The model check used to live in
    // `decode_headers`, reading a field only `body_rewrite::decode_data`
    // ever writes -- and `filter_manager::drive_decode` runs every
    // `decode_headers` before any `decode_data`. So it read `None` on every
    // request and denied all traffic. 18 unit tests missed it because they
    // called `decode_headers` directly after setting the field themselves.

    /// The exact production sequence, with the model published only at the
    /// data phase, as `body_rewrite` really does it. Mutation pin: move the
    /// `authorize_model` call back into `decode_headers` and this reds.
    #[test]
    fn a_permitted_model_published_at_the_data_phase_is_allowed() {
        let policies = policies_map(vec![(
            "tenant-a",
            ModelAccess::Only(vec![ModelPattern::new("gpt-4*")]),
        )]);
        let mut filter = filter_with(policies);
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        cb.set_tenant("tenant-a");

        // Header phase: nothing has published a model yet -- this is the
        // state the old code always saw, and wrongly denied on.
        let mut head = request_headers();
        filter.decode_headers(&mut cb, &mut head, false);
        assert!(
            cb.local_reply.is_none(),
            "the header phase must NOT decide: body_rewrite has not run yet, so a denial \
             here refuses every request in a real chain (the 2026-09-04 P0)"
        );

        // Data phase: `body_rewrite` (earlier in the chain, same trailing
        // loop) publishes the model, then this filter checks it.
        cb.set_requested_model("gpt-4o");
        let mut body = Bytes::new();
        filter.decode_data(&mut cb, &mut body, true);
        assert!(
            cb.local_reply.is_none(),
            "gpt-4o matches the tenant's gpt-4* allow-list and must be permitted"
        );
    }

    /// The denial still happens -- just one phase later. Guards against
    /// "fixing" the P0 by making the filter permissive.
    #[test]
    fn a_denied_model_published_at_the_data_phase_is_still_refused() {
        let policies = policies_map(vec![(
            "tenant-a",
            ModelAccess::Only(vec![ModelPattern::new("gpt-4*")]),
        )]);
        let mut filter = filter_with(policies);
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        cb.set_tenant("tenant-a");
        cb.set_requested_model("claude-3");
        decode_request(&mut filter, &mut cb);
        let reply = cb
            .local_reply
            .expect("claude-3 is outside the gpt-4* allow-list and must be refused");
        assert_eq!(reply.status, HttpStatusCode::FORBIDDEN);
    }

    /// A bodyless request must not slip past the check. `filter_manager`
    /// delivers `decode_data` to every filter in `[0, header_reach)` even
    /// with an empty buffer, so the check still fires and refuses (case 2,
    /// no extractable model). Without that, moving the check off the header
    /// phase would have converted a fail-closed outage into a real bypass.
    #[test]
    fn a_bodyless_request_is_refused_rather_than_slipping_through() {
        let policies = policies_map(vec![(
            "tenant-a",
            ModelAccess::Only(vec![ModelPattern::new("gpt-4*")]),
        )]);
        let mut filter = filter_with(policies);
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        cb.set_tenant("tenant-a");
        // No `set_requested_model` -- nothing published one.
        decode_request(&mut filter, &mut cb);
        let reply = cb
            .local_reply
            .expect("a bodyless request has no model to authorize and must be refused");
        assert_eq!(reply.status, HttpStatusCode::FORBIDDEN);
    }

    /// A trailered request never sees `end_stream` on `decode_data`
    /// (`filter_manager` computes it as `trailers.is_none()`), so the check
    /// has to fire from `decode_trailers` instead. Without that override
    /// this request would reach the upstream unauthorized.
    #[test]
    fn a_trailered_request_is_still_checked_via_decode_trailers() {
        let policies = policies_map(vec![(
            "tenant-a",
            ModelAccess::Only(vec![ModelPattern::new("gpt-4*")]),
        )]);
        let mut filter = filter_with(policies);
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        cb.set_tenant("tenant-a");
        cb.set_requested_model("claude-3");

        let mut head = request_headers();
        filter.decode_headers(&mut cb, &mut head, false);
        // Trailers present, so the data callback is delivered with
        // `end_stream == false` and must NOT decide.
        let mut body = Bytes::new();
        filter.decode_data(&mut cb, &mut body, false);
        assert!(
            cb.local_reply.is_none(),
            "the data phase must not decide while trailers are still coming"
        );

        let mut trailers = RequestTrailers(HeaderMap::new());
        filter.decode_trailers(&mut cb, &mut trailers);
        let reply = cb
            .local_reply
            .expect("a trailered request must still be authorized, via decode_trailers");
        assert_eq!(reply.status, HttpStatusCode::FORBIDDEN);
    }

    /// The check must send at most ONE local reply even though it has three
    /// possible trigger points.
    #[test]
    fn the_check_decides_exactly_once_per_stream() {
        let policies = policies_map(vec![(
            "tenant-a",
            ModelAccess::Only(vec![ModelPattern::new("gpt-4*")]),
        )]);
        let mut filter = filter_with(policies);
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        cb.set_tenant("tenant-a");
        cb.set_requested_model("claude-3");

        let mut head = request_headers();
        filter.decode_headers(&mut cb, &mut head, false);
        let mut body = Bytes::new();
        filter.decode_data(&mut cb, &mut body, true);
        assert!(cb.local_reply.is_some(), "the data phase decides");
        cb.local_reply = None;

        // A second trigger (trailers after an end_stream data call is not a
        // real sequence, but the latch must hold regardless).
        let mut trailers = RequestTrailers(HeaderMap::new());
        filter.decode_trailers(&mut cb, &mut trailers);
        assert!(
            cb.local_reply.is_none(),
            "the decision latch must prevent a second local reply for one stream"
        );
    }

    // --- bootstrap seeding: typed_config.policies still authorizes ---------

    #[test]
    fn typed_config_policies_still_seeds_and_enforces_via_create() {
        let ctx = FactoryContext::default();
        let cp = Arc::new(
            ControlPlane::new(
                Box::new(InMemoryControlPlaneStore::default()),
                HmacSecret::new(b"operator-secret"),
                KeySet::new(),
            )
            .expect("empty store must not fail boot"),
        );
        ctx.get_or_try_init(auth_filter::TYPE_URL, || {
            Ok(Arc::clone(&cp) as Arc<dyn std::any::Any + Send + Sync>)
        })
        .expect("registering the control-plane singleton must succeed");

        let config = model_authz(vec![policy_only("tenant-a", &["gpt-4*"])]);
        let instance_factory = ModelAuthzFilterFactory
            .create(&config, &ctx)
            .expect("valid config must build");
        let mut filter = instance_factory.create_filter();

        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        cb.set_tenant("tenant-a");
        cb.set_requested_model("claude-3");
        decode_request(&mut *filter, &mut cb);
        let reply = cb
            .local_reply
            .expect("typed_config.policies seeded into the store must still deny claude-3");
        assert_eq!(reply.status, HttpStatusCode::FORBIDDEN);
    }
}
