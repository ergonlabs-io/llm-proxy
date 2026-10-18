//! The request-body prefix scanner (`proxy-filters` `body_rewrite.rs`). It
//! reads client bytes to find the routing `model`, the `stream` flag, and the
//! splice point where `stream_options.include_usage` is injected.
//!
//! Input: byte 0 picks the chunk size, byte 1 the scan cap, the rest is the
//! request body.
//!
//! Properties checked beyond "never panic":
//! - the facts do not depend on how the body was chunked;
//! - the splice point lies inside the held prefix;
//! - on a body any JSON decoder accepts, the scanner agrees with serde_json
//!   on the routing `model` (last key wins, a non-string clears it), and the
//!   spliced body is still a JSON object.
#![no_main]

use libfuzzer_sys::fuzz_target;
use proxy_filters::body_rewrite::{
    include_usage_injection, BodyFacts, BodyPrefixScanner, ScanOutcome, DEFAULT_PREFIX_CAP,
};

fn scan(body: &[u8], chunk: usize, cap: usize) -> (BodyFacts, usize) {
    let mut scanner = BodyPrefixScanner::new(cap);
    for piece in body.chunks(chunk) {
        scanner.push(piece);
    }
    let held = scanner.held().len();
    (scanner.finish(), held)
}

fuzz_target!(|data: &[u8]| {
    let [chunk, cap, body @ ..] = data else {
        return;
    };
    // Small caps exercise CapExceeded; 0 selects the production default.
    let cap = match *cap {
        0 => DEFAULT_PREFIX_CAP,
        n => usize::from(n),
    };
    let (whole, held) = scan(body, body.len().max(1), cap);
    let (pieces, _) = scan(body, usize::from(*chunk).max(1), cap);
    assert_eq!(whole, pieces, "facts depend on chunking");
    if let Some(at) = whole.splice_at {
        assert!(at <= held, "splice point {at} beyond held prefix {held}");
    }

    if cap != DEFAULT_PREFIX_CAP || body.len() >= cap {
        return;
    }
    let Ok(serde_json::Value::Object(object)) = serde_json::from_slice(body) else {
        return;
    };
    assert_eq!(whole.outcome, ScanOutcome::Complete, "valid object not Complete");
    let expected_model = object.get("model").and_then(|m| m.as_str());
    assert_eq!(
        whole.model.as_deref(),
        expected_model,
        "routing model disagrees with the decoder"
    );
    if let Some(inject) = include_usage_injection(&whole) {
        let at = whole.splice_at.expect("injection implies a splice point");
        let mut spliced = body[..at].to_vec();
        spliced.extend_from_slice(inject.as_bytes());
        spliced.extend_from_slice(&body[at..]);
        assert!(
            matches!(
                serde_json::from_slice(&spliced),
                Ok(serde_json::Value::Object(_))
            ),
            "splice broke a valid body: {:?}",
            String::from_utf8_lossy(&spliced)
        );
    }
});
