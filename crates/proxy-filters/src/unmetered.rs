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

/// Whether a spend budget can count `endpoint`. Phase 1 meters the five text
/// endpoints; images and audio join in later phases (ADR-0010 "Phasing").
pub(crate) fn metered_under_spend(endpoint: Endpoint) -> bool {
    endpoint.reports_text_tokens()
}

/// Whether a token limit can count `endpoint`. Token limits count tokens
/// only, and only the text endpoints report them for every model, so this
/// set stays at the five text endpoints (ADR-0010 decision 1).
pub(crate) fn metered_under_token_limit(endpoint: Endpoint) -> bool {
    endpoint.reports_text_tokens()
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
