//! The one 429 the proxy's own limit filters send.
//!
//! `llmproxy.token_limit` and `llmproxy.spend_limit` both refuse here, so a
//! client sees the same shape whichever control refused:
//!
//! - A JSON body in the client's API shape. A request to `.../messages`
//!   (Anthropic Messages) gets `{"type":"error","error":{"type":
//!   "rate_limit_error","message","code"}}`; every other endpoint gets
//!   OpenAI's `{"error":{"message","type","code"}}`. The shape follows the
//!   client-facing endpoint ([`Endpoint::classify`]), because that is the API
//!   the client's SDK speaks. The provider behind the route is not known yet
//!   when a control refuses, and a failover chain can change it.
//! - A stable `code` per cause: `request_limit_exceeded`,
//!   `token_limit_exceeded`, `concurrency_limit_exceeded`,
//!   `spend_budget_exceeded`. The same string is the local-reply detail, so
//!   `%RESPONSE_CODE_DETAILS%` carries it.
//! - `retry-after` and `x-should-retry`. The official OpenAI and Anthropic
//!   SDKs ignore a `retry-after` above 60 seconds and read `x-should-retry`,
//!   so a wait longer than [`MAX_SDK_RETRY_SECS`] says `false`: retrying a
//!   daily limit inside a client's backoff loop only burns requests.
//!
//! Dimension headers differ per cause and are built by [`Reply::window`] and
//! [`Reply::budget`].

use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use proxy_http::endpoint::Endpoint;
use proxy_http::filter::DecoderCallbacks;
use proxy_http::stream_info::PreparedReply;

/// The longest `retry-after`, in seconds, the official SDKs act on. A longer
/// wait is advertised with `x-should-retry: false`.
pub(crate) const MAX_SDK_RETRY_SECS: u64 = 60;

/// Which limit refused. Selects the body message, the stable code and the
/// local-reply detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cause {
    Requests,
    Tokens,
    Streams,
    Spend,
}

impl Cause {
    pub(crate) fn message(self) -> &'static str {
        match self {
            Cause::Tokens => "token budget exceeded",
            Cause::Requests => "request rate exceeded",
            Cause::Streams => "too many concurrent streams",
            Cause::Spend => "spend budget exceeded",
        }
    }

    /// The stable machine-readable code, also the local-reply detail.
    pub(crate) fn code(self) -> &'static str {
        match self {
            Cause::Tokens => "token_limit_exceeded",
            Cause::Requests => "request_limit_exceeded",
            Cause::Streams => "concurrency_limit_exceeded",
            Cause::Spend => "spend_budget_exceeded",
        }
    }
}

/// A 429 ready to send: the cause plus the headers its limit publishes.
#[derive(Debug)]
#[must_use = "a Reply does nothing until `send` is called"]
pub(crate) struct Reply {
    cause: Cause,
    retry_after_secs: u64,
    headers: Vec<(HeaderName, HeaderValue)>,
}

impl Reply {
    /// A refusal by a counted window (requests, tokens or streams).
    ///
    /// Sends the unsuffixed `x-ratelimit-*` set, deprecated and kept for one
    /// minor release, and, for requests and tokens, the suffixed set the
    /// OpenAI SDKs read: `x-ratelimit-{limit,remaining,reset}-{requests,
    /// tokens}`. A stream (concurrency) refusal has no suffixed dimension.
    pub(crate) fn window(
        cause: Cause,
        limit: u64,
        remaining: u64,
        reset_secs: u64,
        retry_after_secs: u64,
    ) -> Self {
        let mut headers = vec![
            (
                HeaderName::from_static("x-ratelimit-limit"),
                HeaderValue::from(limit),
            ),
            (
                HeaderName::from_static("x-ratelimit-remaining"),
                HeaderValue::from(remaining),
            ),
            (
                HeaderName::from_static("x-ratelimit-reset"),
                HeaderValue::from(reset_secs),
            ),
        ];
        let suffixed = match cause {
            Cause::Requests => Some([
                "x-ratelimit-limit-requests",
                "x-ratelimit-remaining-requests",
                "x-ratelimit-reset-requests",
            ]),
            Cause::Tokens => Some([
                "x-ratelimit-limit-tokens",
                "x-ratelimit-remaining-tokens",
                "x-ratelimit-reset-tokens",
            ]),
            Cause::Streams | Cause::Spend => None,
        };
        if let Some([limit_name, remaining_name, reset_name]) = suffixed {
            headers.push((
                HeaderName::from_static(limit_name),
                HeaderValue::from(limit),
            ));
            headers.push((
                HeaderName::from_static(remaining_name),
                HeaderValue::from(remaining),
            ));
            headers.push((
                HeaderName::from_static(reset_name),
                HeaderValue::from(reset_secs),
            ));
        }
        Reply {
            cause,
            retry_after_secs,
            headers,
        }
    }

    /// A refusal by a spend budget. The values are micro-dollars on the
    /// inside and USD on the wire. These headers replace `x-ratelimit-*`,
    /// whose names say request or token counts, not money.
    pub(crate) fn budget(
        limit_micros: u64,
        remaining_micros: u64,
        reset_secs: u64,
        retry_after_secs: u64,
    ) -> Self {
        Reply {
            cause: Cause::Spend,
            retry_after_secs,
            headers: vec![
                (
                    HeaderName::from_static("x-llmproxy-budget-limit-usd"),
                    usd(limit_micros),
                ),
                (
                    HeaderName::from_static("x-llmproxy-budget-remaining-usd"),
                    usd(remaining_micros),
                ),
                (
                    HeaderName::from_static("x-llmproxy-budget-reset"),
                    HeaderValue::from(reset_secs),
                ),
            ],
        }
    }

    /// Names the spend budget that refused: `x-llmproxy-budget-scope` is
    /// `key`, `tenant` or `scoped`, and a scoped budget adds its name in
    /// `x-llmproxy-budget-name`. The amounts stay in the other
    /// `x-llmproxy-budget-*` headers; nothing here is an `x-ratelimit-*`.
    pub(crate) fn budget_scope(mut self, scope: BudgetScope<'_>) -> Self {
        let (scope, name) = match scope {
            BudgetScope::Key => ("key", None),
            BudgetScope::Tenant => ("tenant", None),
            BudgetScope::Scoped(name) => ("scoped", Some(name)),
        };
        self.headers.push((
            HeaderName::from_static("x-llmproxy-budget-scope"),
            HeaderValue::from_static(scope),
        ));
        // A scoped budget name is lowercase ASCII (`ScopedBudget::
        // is_valid_name`), so the conversion only fails on a value the store
        // never holds; such a reply simply omits the name.
        if let Some(Ok(value)) = name.map(HeaderValue::from_str) {
            self.headers
                .push((HeaderName::from_static("x-llmproxy-budget-name"), value));
        }
        self
    }

    /// Send the 429. `message` replaces the cause's default text when the
    /// caller knows more (for example which period refused).
    pub(crate) fn send(self, cb: &mut dyn DecoderCallbacks, message: Option<&str>) {
        let endpoint = cb.stream_info().llm.endpoint;
        let code = self.cause.code();
        let (body, headers) = self.into_parts(endpoint, message);
        cb.send_local_reply_exact(
            StatusCode::TOO_MANY_REQUESTS,
            &body,
            Some(Box::new(move |map: &mut HeaderMap| {
                for (name, value) in &headers {
                    map.insert(name.clone(), value.clone());
                }
            })),
            code,
        );
    }

    /// The same reply, built for a later stage to send: the router sends it
    /// when a spent provider budget leaves no cluster to dial.
    pub(crate) fn prepare(self, endpoint: Endpoint) -> PreparedReply {
        let details = self.cause.code();
        let (body, headers) = self.into_parts(endpoint, None);
        PreparedReply {
            status: StatusCode::TOO_MANY_REQUESTS,
            headers,
            body: bytes::Bytes::from(body),
            details,
            flag: proxy_observability::ResponseFlag::RateLimited,
        }
    }

    fn into_parts(self, endpoint: Endpoint, message: Option<&str>) -> (String, HeaderMap) {
        let body = body(
            endpoint,
            message.unwrap_or_else(|| self.cause.message()),
            self.cause.code(),
        );
        let mut map = HeaderMap::new();
        map.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        for (name, value) in self.headers {
            map.insert(name, value);
        }
        map.insert("retry-after", HeaderValue::from(self.retry_after_secs));
        map.insert(
            "x-should-retry",
            HeaderValue::from_static(should_retry(self.retry_after_secs)),
        );
        (body, map)
    }
}

/// Which spend budget a 429 names; see [`Reply::budget_scope`].
#[derive(Debug, Clone, Copy)]
pub(crate) enum BudgetScope<'a> {
    Key,
    Tenant,
    Scoped(&'a str),
}

impl Reply {}

/// `x-should-retry` for a wait of `retry_after_secs`.
fn should_retry(retry_after_secs: u64) -> &'static str {
    if retry_after_secs > MAX_SDK_RETRY_SECS {
        "false"
    } else {
        "true"
    }
}

/// Micro-dollars as a decimal USD string, exact, with no float rounding:
/// `1_500_000` is `"1.500000"`.
fn usd(micros: u64) -> HeaderValue {
    // Rust note: ASCII digits and a dot are always a valid header value, so
    // the conversion cannot fail; the fallback only satisfies the type.
    HeaderValue::from_str(&format!("{}.{:06}", micros / 1_000_000, micros % 1_000_000))
        .unwrap_or_else(|_| HeaderValue::from_static("0"))
}

/// The JSON error body for `endpoint`'s API shape.
fn body(endpoint: Endpoint, message: &str, code: &str) -> String {
    let value = match endpoint {
        Endpoint::Messages => serde_json::json!({
            "type": "error",
            "error": { "type": "rate_limit_error", "message": message, "code": code },
        }),
        _ => serde_json::json!({
            "error": { "message": message, "type": "rate_limit_error", "code": code },
        }),
    };
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Micro-dollar amounts render exactly, including sub-dollar and zero.
    #[test]
    fn usd_renders_micro_dollars_exactly() {
        for (micros, want) in [
            (0, "0.000000"),
            (1, "0.000001"),
            (1_500_000, "1.500000"),
            (123_456_789, "123.456789"),
        ] {
            assert_eq!(usd(micros), want, "{micros} micro-dollars");
        }
    }

    /// The boundary is exclusive: the SDKs retry up to and including 60 s.
    #[test]
    fn should_retry_flips_above_sixty_seconds() {
        assert_eq!(should_retry(0), "true");
        assert_eq!(should_retry(60), "true");
        assert_eq!(should_retry(61), "false");
    }
}
