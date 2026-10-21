//! Refusal of endpoints a spend budget or token limit cannot count
//! (ADR-0010 decision 1).
//!
//! A control that admits a request it cannot meter charges it zero, which is
//! a bypass, not a degraded meter. So the spend and token-limit filters each
//! refuse, with 403 `endpoint_not_metered`, a request that the control binds
//! and whose [`Endpoint`] is outside that control's metered set. The refusal
//! is visible in the access log (`%RESPONSE_CODE_DETAILS%`) and in
//! `llmproxy_unmetered_endpoint_refused_total{endpoint, control}`.
//!
//! A request no budget or limit binds is never refused here and logs nothing
//! (AGENTS.md "Fail-open controls": silent where the control was never meant
//! to apply). [`Endpoint::Free`] paths are exempt: no provider bills them.
//!
//! There is deliberately no exemption for direct-response routes. The route
//! seen at `decode_headers` is provisional, because `body_rewrite` publishes
//! the model at the end of the body and clears the route cache, so a POST
//! that matches the synthetic 404 now can still be routed to a provider.

use std::sync::Arc;

use http::StatusCode;
use proxy_http::endpoint::Endpoint;
use proxy_http::filter::DecoderCallbacks;
use proxy_http::stream_info::RequestFacts;
use proxy_observability::stats::{instruments, Registry, WorkerId};

/// The response-code detail of every refusal. It names no control, because
/// both controls share it; the counter's `control` label says which refused.
pub(crate) const DETAILS: &str = "endpoint_not_metered";

const BODY: &str =
    "this endpoint cannot be metered, so it is refused under a spend budget or token limit";

/// The control that refused, for the counter's `control` label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Control {
    Spend,
    TokenLimit,
}

impl Control {
    fn label(self) -> &'static str {
        match self {
            Control::Spend => "spend",
            Control::TokenLimit => "token_limit",
        }
    }
}

/// Whether a spend budget can count `endpoint`: the five text endpoints,
/// image generation and edits (tokens or images), speech (characters or
/// tokens), transcription and translation (audio duration or tokens)
/// (ADR-0010 phase 3), and realtime sessions (tokens from their event
/// frames, ADR-0015). Batch and every unknown path stay out.
pub(crate) fn metered_under_spend(endpoint: Endpoint) -> bool {
    endpoint.reports_text_tokens()
        || matches!(
            endpoint,
            Endpoint::ImageGeneration
                | Endpoint::ImageEdit
                | Endpoint::Speech
                | Endpoint::Transcription
                | Endpoint::Translation
                | Endpoint::Realtime
        )
}

/// The endpoints whose countability under a spend budget depends on the
/// body, so it is decided at the end of the body (ADR-0010 decision 1, "Two
/// admission points").
pub(crate) fn needs_body_facts(endpoint: Endpoint) -> bool {
    matches!(
        endpoint,
        Endpoint::ImageEdit | Endpoint::Speech | Endpoint::Transcription | Endpoint::Translation
    )
}

/// Whether the request's shape can be counted under a spend budget
/// (ADR-0010 decision 5). `model_proven` says the body scan proved the
/// model: without it the request cannot be priced, and this check does not
/// rely on `model_authz`, which may not be configured.
///
/// - Image edits: the images are counted from the response.
/// - Speech: the `input` characters, proven by a scan that read the whole
///   body.
/// - Transcription: a `response_format` whose response carries usage
///   (`json`, the default when absent, `verbose_json`, `diarized_json`).
///   `text`, `srt` and `vtt` carry none.
/// - Translation: only `verbose_json` carries usage (`duration`).
///
/// Every other endpoint is decided at headers and passes here.
pub(crate) fn countable_under_spend(
    endpoint: Endpoint,
    model_proven: bool,
    facts: &RequestFacts,
) -> bool {
    let response_format = facts.response_format.as_deref();
    match endpoint {
        Endpoint::ImageEdit => model_proven,
        Endpoint::Speech => model_proven && facts.input_characters.is_some(),
        Endpoint::Transcription => {
            model_proven
                && match response_format {
                    None => facts.complete,
                    Some(format) => matches!(format, "json" | "verbose_json" | "diarized_json"),
                }
        }
        Endpoint::Translation => model_proven && response_format == Some("verbose_json"),
        _ => true,
    }
}

/// Whether a token limit can count `endpoint`. Token limits count tokens
/// only, and only the text endpoints and realtime sessions report them for
/// every model (ADR-0010 decision 1, ADR-0015).
pub(crate) fn metered_under_token_limit(endpoint: Endpoint) -> bool {
    // A realtime session reports tokens for every model too, in its
    // `response.done` events (ADR-0015).
    endpoint.reports_text_tokens() || endpoint == Endpoint::Realtime
}

/// `llmproxy_unmetered_endpoint_refused_total`. Series are resolved on the
/// refusal path only, so admitted traffic never touches the registry lock.
pub(crate) struct RefusalCounter {
    registry: Arc<Registry>,
}

impl RefusalCounter {
    /// Endpoint classes times controls; the label set is closed.
    const SERIES_CEILING: usize = 32;

    pub(crate) fn new(registry: Arc<Registry>) -> Self {
        Self { registry }
    }

    fn incr(&self, endpoint: Endpoint, control: Control) {
        let handle = self.registry.resolve_capped(
            &instruments::UNMETERED_ENDPOINT_REFUSED,
            &[("endpoint", endpoint.label()), ("control", control.label())],
            Self::SERIES_CEILING,
            &[("endpoint", "other"), ("control", control.label())],
        );
        self.registry.incr(WorkerId(0), handle, 1);
    }
}

/// Refuse `endpoint` for `control`: count it and send the local 403.
pub(crate) fn refuse(
    cb: &mut dyn DecoderCallbacks,
    endpoint: Endpoint,
    control: Control,
    counter: Option<&RefusalCounter>,
) {
    if let Some(counter) = counter {
        counter.incr(endpoint, control);
    }
    cb.send_local_reply(StatusCode::FORBIDDEN, BODY, None, DETAILS);
}
