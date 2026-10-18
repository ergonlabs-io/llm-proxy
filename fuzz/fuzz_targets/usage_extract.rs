//! SSE and JSON usage extraction (`proxy-filters` `usage.rs`). These parsers
//! read provider bytes and their output drives spend and the billing ledger.
//!
//! Input: byte 0 picks the dialect, byte 1 the chunk size used to replay the
//! body into the streaming scanner, the rest is the response body.
//!
//! Beyond "never panic", the target checks properties production relies on:
//! - the scanner's answer does not depend on how the body was chunked;
//! - every kept provider value respects its documented bound.
#![no_main]

use libfuzzer_sys::fuzz_target;
use proxy_filters::usage::{
    extract_json_served_model, extract_json_upstream, extract_json_upstream_from_tail,
    extract_json_usage, extract_json_usage_from_tail, Dialect, SseUsageScanner,
    UpstreamEvidence, MAX_SERVED_MODEL_BYTES, MAX_SSE_LINE_BYTES, MAX_UPSTREAM_ID_BYTES,
    MAX_UPSTREAM_USAGE_BYTES,
};

fn check_bounds(evidence: &UpstreamEvidence) {
    if let Some(id) = &evidence.response_id {
        assert!(!id.is_empty() && id.len() <= MAX_UPSTREAM_ID_BYTES);
        assert!(!id.chars().any(char::is_control));
    }
    if let Some(usage) = &evidence.usage_json {
        assert!(usage.len() <= MAX_UPSTREAM_USAGE_BYTES);
        assert!(!usage.contains(['\n', '\r']), "usage_json must be one line");
        assert!(
            serde_json::from_str::<serde_json::Value>(usage).is_ok(),
            "usage_json must still be valid JSON: {usage:?}"
        );
    }
}

fn check_model(model: &Option<String>) {
    if let Some(model) = model {
        assert!(!model.is_empty() && model.len() <= MAX_SERVED_MODEL_BYTES);
        assert!(!model.chars().any(char::is_control));
    }
}

fn scan(dialect: Dialect, body: &[u8], chunk: usize) -> SseUsageScanner {
    let mut scanner = SseUsageScanner::new(dialect);
    for piece in body.chunks(chunk) {
        scanner.push(piece);
    }
    scanner
}

fuzz_target!(|data: &[u8]| {
    let [selector, chunk, body @ ..] = data else {
        return;
    };
    let dialect = match selector % 3 {
        0 => Dialect::OpenAi,
        1 => Dialect::Anthropic,
        _ => Dialect::OpenAiResponses,
    };

    // Whole-body and tail paths.
    let _ = extract_json_usage(dialect, body);
    let _ = extract_json_usage_from_tail(dialect, body);
    check_model(&extract_json_served_model(body));
    check_bounds(&extract_json_upstream(body));
    check_bounds(&extract_json_upstream_from_tail(body));

    // Streaming path, fed whole and fed in chunks.
    let whole = scan(dialect, body, body.len().max(1));
    let pieces = scan(dialect, body, usize::from(*chunk).max(1));
    check_model(&whole.served_model());
    check_bounds(&whole.upstream());
    check_bounds(&pieces.upstream());

    // The line cap discards an over-long partial line between pushes, which
    // can legitimately differ by chunking; below it the answer must not.
    if body.len() < MAX_SSE_LINE_BYTES {
        assert_eq!(whole.usage(), pieces.usage(), "usage depends on chunking");
        assert_eq!(whole.served_model(), pieces.served_model());
        assert_eq!(whole.upstream(), pieces.upstream());
        assert_eq!(whole.streamed_text_bytes(), pieces.streamed_text_bytes());
    }
});
