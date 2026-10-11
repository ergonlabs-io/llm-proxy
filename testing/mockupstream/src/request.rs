//! Minimal request-body introspection.
//!
//! This crate needs exactly two facts out of a request body -- `stream` and
//! `model` -- and the crate doc's rule is that the body is never
//! retained past learning them. Keeping that parse as its own pure function
//! (no I/O, no async) makes it unit-testable without a server, and keeps
//! `handler.rs`'s body-reading code from also having to think about JSON
//! shape.

use serde::Deserialize;

/// Upper bound on a request body this crate will read. Anything larger gets
/// a 413 before a single byte past the limit is retained -- protects a
/// long-lived process from a client (or misconfigured driver) sending an
/// unbounded body.
pub const MAX_BODY_BYTES: usize = 1 << 20; // 1 MiB

/// The only two fields this mock upstream ever looks at. Every other field
/// a real request carries (`messages`, `max_tokens`, ...) is ignored -- this
/// is a load-testing stand-in, not a schema validator.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct RequestMeta {
    #[serde(default)]
    pub stream: bool,
    #[serde(default = "default_model")]
    pub model: String,
}

fn default_model() -> String {
    "mock-model".to_string()
}

impl Default for RequestMeta {
    /// Matches the field-level `serde(default)`s above, so a body that fails
    /// to parse at all behaves exactly like one that parsed with neither
    /// field present.
    fn default() -> Self {
        Self {
            stream: false,
            model: default_model(),
        }
    }
}

/// Parse just enough of `body` to learn `stream`/`model`.
///
/// Malformed JSON, or JSON that isn't an object (an array, a bare string,
/// ...), falls back to [`RequestMeta::default`] rather than erroring -- this
/// mock upstream exists to be dialled by a load generator, not to validate
/// its callers, and a body it can't make sense of should behave exactly like
/// a body with neither field set.
pub fn parse_request_meta(body: &[u8]) -> RequestMeta {
    serde_json::from_slice(body).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_stream_and_model() {
        let meta = parse_request_meta(br#"{"stream":true,"model":"gpt-4o-mini"}"#);
        assert_eq!(
            meta,
            RequestMeta {
                stream: true,
                model: "gpt-4o-mini".to_string(),
            }
        );
    }

    #[test]
    fn missing_fields_default() {
        let meta = parse_request_meta(br#"{"messages":[]}"#);
        assert_eq!(meta, RequestMeta::default());
        assert!(!meta.stream);
        assert_eq!(meta.model, "mock-model");
    }

    #[test]
    fn ignores_extra_fields() {
        let meta = parse_request_meta(
            br#"{"model":"claude-3","messages":[{"role":"user","content":"hi"}],"max_tokens":10}"#,
        );
        assert_eq!(meta.model, "claude-3");
        assert!(!meta.stream);
    }

    #[test]
    fn malformed_json_defaults_rather_than_panicking() {
        for body in [&b"not json"[..], &b"{"[..], &b""[..], &[0xff, 0xfe][..]] {
            assert_eq!(parse_request_meta(body), RequestMeta::default(), "{body:?}");
        }
    }

    #[test]
    fn non_object_json_defaults() {
        assert_eq!(parse_request_meta(b"[1,2,3]"), RequestMeta::default());
        assert_eq!(parse_request_meta(b"\"a string\""), RequestMeta::default());
        assert_eq!(parse_request_meta(b"null"), RequestMeta::default());
    }

    #[test]
    fn stream_false_explicit() {
        let meta = parse_request_meta(br#"{"stream":false}"#);
        assert!(!meta.stream);
    }
}
