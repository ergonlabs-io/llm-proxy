//! The router's whole-body handling (`proxy-http` `router.rs`), reached
//! through its `fuzzing` module: `reconcile_request_body` (the routed model
//! must be the body's model, the output-token cap, forced
//! `stream_options.include_usage`) and `prepare_attempt_body` (the selected
//! cluster's request-field policy and model rewrite). The client writes the
//! body; these functions decide what the provider decodes and what is billed.
//!
//! Input: byte 0 holds flags, byte 1 the cap, bytes 2 and 3 the deny and
//! strip key masks, byte 4 the rewrite pattern; the rest is the body.
//!
//! The oracle is `serde_json::Value`, the decoder a provider is assumed to
//! use. Properties checked beyond "never panic":
//! - reconcile refuses only when a check applies, and what it accepts names
//!   the routed model and keeps every output-token limit within the cap;
//! - a replacement body is the original with `stream_options.include_usage`
//!   set and nothing else changed, and forced usage is never skipped on a
//!   streaming JSON object;
//! - an attempt body never carries a denied or stripped key, carries the
//!   cluster's upstream model when a rewrite applies, and otherwise keeps the
//!   client's fields; with nothing to do it is the client's bytes unchanged.
#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use proxy_config::ir::{ProviderModelRewrite, ProviderRuntimeConfig, RequestFieldPolicy};
use proxy_http::endpoint::Endpoint;
use proxy_http::router::fuzzing::{
    prepare_attempt_body, provider_model_pattern_matches, reconcile_request_body, BodyRefusal,
};
use serde_json::{Map, Value};

const KEYS: [&str; 8] = [
    "tools",
    "metadata",
    "user",
    "temperature",
    "stream_options",
    "max_tokens",
    "store",
    "n",
];
const PATTERNS: [&str; 4] = ["*", "gpt-*", "gpt-4o", "claude*"];
const UPSTREAM: &str = "upstream-model";
const RESOLVED: &str = "resolved-model";

fn output_fields(endpoint: Endpoint) -> &'static [&'static str] {
    match endpoint {
        Endpoint::Responses => &["max_output_tokens"],
        Endpoint::Messages => &["max_tokens"],
        _ => &["max_completion_tokens", "max_tokens"],
    }
}

fn without(object: &Map<String, Value>, keys: &[&str]) -> Map<String, Value> {
    let mut object = object.clone();
    for key in keys {
        object.remove(*key);
    }
    object
}

fn check_reconcile(
    body: &Bytes,
    value: Option<&Map<String, Value>>,
    requested: Option<&str>,
    force: bool,
    cap: Option<u32>,
    endpoint: Endpoint,
) {
    let result = reconcile_request_body(body, requested, force, cap, endpoint);
    if requested.is_none() && !force && cap.is_none() {
        assert_eq!(
            result,
            Ok(None),
            "nothing to check, yet the body was touched"
        );
        return;
    }
    let Ok(replacement) = result else {
        assert!(
            requested.is_some() || cap.is_some(),
            "refused with no model or cap to check: {result:?}"
        );
        return;
    };
    // serde_json's `Value` refuses some JSON the router's skip-only scan
    // accepts (a number out of `f64` range); the oracle cannot judge those.
    let Some(value) = value else {
        return;
    };
    if let Some(requested) = requested {
        let object = value;
        assert_eq!(
            object.get("model").and_then(Value::as_str),
            Some(requested),
            "accepted a body whose model is not the routed model"
        );
    }
    if let (Some(cap), object) = (cap, value) {
        for field in output_fields(endpoint) {
            if let Some(limit) = object.get(*field) {
                let within = limit.as_u64().is_some_and(|n| n <= u64::from(cap));
                assert!(within, "accepted `{field}` {limit} over the cap {cap}");
            }
        }
    }
    match replacement {
        Some(new) => {
            let object = value;
            let Ok(Value::Object(new)) = serde_json::from_slice::<Value>(&new) else {
                panic!("replacement is not a JSON object");
            };
            assert_eq!(
                new.get("stream_options")
                    .and_then(|o| o.get("include_usage")),
                Some(&Value::Bool(true))
            );
            assert_eq!(
                without(&new, &["stream_options"]),
                without(object, &["stream_options"]),
                "the rewrite changed more than stream_options"
            );
            if let Some(Value::Object(old)) = object.get("stream_options") {
                let new = new["stream_options"].as_object().expect("object");
                assert_eq!(
                    without(new, &["include_usage"]),
                    without(old, &["include_usage"])
                );
            }
        }
        None => {
            if let (true, object) = (force, value) {
                let streaming = object.get("stream") == Some(&Value::Bool(true));
                let opted_in = object
                    .get("stream_options")
                    .and_then(|o| o.get("include_usage"))
                    == Some(&Value::Bool(true));
                assert!(
                    !streaming || opted_in,
                    "forced usage reporting was skipped on a streaming body"
                );
            }
        }
    }
}

fn check_attempt(
    body: &Bytes,
    value: Option<&Map<String, Value>>,
    runtime: Option<&ProviderRuntimeConfig>,
    requested: Option<&str>,
    resolved: Option<&str>,
) {
    let result = prepare_attempt_body(runtime, requested, resolved, body);
    let policy = runtime
        .map(|r| &r.request_field_policy)
        .filter(|p| !p.is_empty());
    let upstream = requested.and_then(|requested| {
        let routing = resolved.unwrap_or(requested);
        runtime
            .and_then(|r| {
                r.model_rewrites
                    .iter()
                    .find(|m| provider_model_pattern_matches(&m.pattern, routing))
                    .map(|m| m.upstream_model.as_str())
            })
            .or(resolved)
    });

    if policy.is_none() && upstream.is_none() {
        assert_eq!(
            result.as_ref().ok(),
            Some(body),
            "nothing to do, yet the body changed"
        );
        return;
    }
    if let (Some(policy), Some(object)) = (policy, value) {
        if let Some(denied) = policy.deny.iter().find(|k| object.contains_key(k.as_str())) {
            assert!(
                matches!(&result, Err(BodyRefusal::FieldNotPermitted(_))),
                "denied key `{denied}` was not refused: {result:?}"
            );
            return;
        }
    }
    let Ok(out) = result else {
        return;
    };
    // As in `check_reconcile`: no `Value` oracle for this body.
    let Some(object) = value else {
        return;
    };
    let Ok(Value::Object(out)) = serde_json::from_slice::<Value>(&out) else {
        panic!("attempt body is not a JSON object");
    };
    let mut removed: Vec<&str> = Vec::new();
    if let Some(policy) = policy {
        for key in policy.deny.iter().chain(&policy.strip) {
            assert!(!out.contains_key(key.as_str()), "attempt body kept `{key}`");
            removed.push(key);
        }
    }
    if let (Some(requested), Some(upstream)) = (requested, upstream) {
        assert_eq!(object.get("model").and_then(Value::as_str), Some(requested));
        assert_eq!(out.get("model").and_then(Value::as_str), Some(upstream));
        removed.push("model");
    }
    assert_eq!(
        without(&out, &removed),
        without(object, &removed),
        "the attempt body changed a field the policy and rewrite do not name"
    );
}

fuzz_target!(|data: &[u8]| {
    let [flags, cap, deny, strip, rewrite, body @ ..] = data else {
        return;
    };
    let body = Bytes::copy_from_slice(body);
    let value = match serde_json::from_slice::<Value>(&body) {
        Ok(Value::Object(object)) => Some(object),
        _ => None,
    };
    let endpoint = match (flags >> 3) & 3 {
        0 => Endpoint::ChatCompletions,
        1 => Endpoint::Completions,
        2 => Endpoint::Responses,
        _ => Endpoint::Messages,
    };
    // The router routes on the model the prefix scanner read, so usually the
    // body's own; sometimes a different one, to drive the disagreement path.
    let body_model = value
        .as_ref()
        .and_then(|o| o.get("model"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let requested = match (flags & 1 != 0, flags & 0x20 != 0) {
        (false, _) => None,
        (true, false) => Some(body_model.unwrap_or_else(|| "gpt-4o".to_string())),
        (true, true) => Some("gpt-4o".to_string()),
    };
    let force = flags & 2 != 0;
    let cap = (flags & 4 != 0).then_some(u32::from(*cap));
    check_reconcile(
        &body,
        value.as_ref(),
        requested.as_deref(),
        force,
        cap,
        endpoint,
    );

    let pick = |mask: u8| -> Vec<String> {
        KEYS.iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, k)| k.to_string())
            .collect()
    };
    let runtime = (flags & 0x40 != 0).then(|| ProviderRuntimeConfig {
        credential: None,
        path_template: None,
        model_rewrites: match rewrite % 5 {
            4 => Vec::new(),
            i => vec![ProviderModelRewrite {
                pattern: PATTERNS[usize::from(i)].to_string(),
                upstream_model: UPSTREAM.to_string(),
            }],
        },
        // The loader keeps the two lists disjoint.
        request_field_policy: RequestFieldPolicy {
            deny: pick(*deny),
            strip: pick(*strip & !*deny),
        },
        tenant_credential: None,
    });
    let resolved = (flags & 0x80 != 0).then_some(RESOLVED);
    check_attempt(
        &body,
        value.as_ref(),
        runtime.as_ref(),
        requested.as_deref(),
        resolved,
    );
});
