//! Entry points for the cargo-fuzz targets in `fuzz/`. Not a public API: the
//! module exists only with the `fuzzing` feature (and under `test`). Each
//! function forwards to the router's private body handling unchanged and only
//! flattens its private error types, so the fuzzer exercises the code a
//! request runs.

use bytes::Bytes;

use crate::endpoint::Endpoint;

/// Why [`reconcile_request_body`] refused a body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub message: String,
    /// Refused by the output-token cap rather than the model check.
    pub output_cap: bool,
}

/// The router's whole-body reconcile (`router::reconcile_request_body`).
pub fn reconcile_request_body(
    body: &Bytes,
    requested_model: Option<&str>,
    force_include_usage: bool,
    max_output_tokens: Option<u32>,
    endpoint: Endpoint,
) -> Result<Option<Bytes>, Refusal> {
    super::reconcile_request_body(
        body,
        requested_model,
        force_include_usage,
        max_output_tokens,
        endpoint,
    )
    .map_err(|refusal| Refusal {
        message: refusal.message,
        output_cap: refusal.output_cap,
    })
}

/// Why [`prepare_attempt_body`] refused a body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyRefusal {
    FieldNotPermitted(String),
    Invalid(String),
}

/// The per-attempt body rewrite for the selected cluster
/// (`router::prepare_attempt_body`).
pub fn prepare_attempt_body(
    runtime: Option<&proxy_config::ir::ProviderRuntimeConfig>,
    requested_model: Option<&str>,
    resolved_model: Option<&str>,
    body: &Bytes,
) -> Result<Bytes, BodyRefusal> {
    super::prepare_attempt_body(runtime, requested_model, resolved_model, body).map_err(|refusal| {
        match refusal {
            super::BodyRefusal::FieldNotPermitted(field) => BodyRefusal::FieldNotPermitted(field),
            super::BodyRefusal::Invalid(message) => BodyRefusal::Invalid(message),
        }
    })
}

/// The cluster model-rewrite pattern match (`router::provider_model_pattern_matches`).
pub fn provider_model_pattern_matches(pattern: &str, model: &str) -> bool {
    super::provider_model_pattern_matches(pattern, model)
}
