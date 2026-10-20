//! The structural media response scanners (`proxy-filters` `media_scan.rs`).
//! They read provider bytes of image responses that are too large to hold, so
//! they must stay bounded and never invent facts.
//!
//! Input: byte 0 picks the chunk size, the rest is the response body, fed to
//! both the JSON scanner and the SSE scanner.
//!
//! Properties checked beyond "never panic":
//! - the facts do not depend on how the body was chunked;
//! - the kept `usage` and scalars stay within their bounds;
//! - on a body serde_json accepts as an object, the scanner agrees with it on
//!   the number of top-level `data` elements, on any `size` it kept, and on
//!   a numeric top-level `duration`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use proxy_filters::media_scan::{
    seconds_to_millis, MediaJsonScanner, MediaSseScanner, MAX_SCALAR_BYTES, MAX_USAGE_OBJECT_BYTES,
};

fuzz_target!(|data: &[u8]| {
    let [chunk, body @ ..] = data else {
        return;
    };
    let chunk = usize::from(*chunk).max(1);

    let mut whole = MediaJsonScanner::new();
    whole.push(body);
    let mut pieces = MediaJsonScanner::new();
    for piece in body.chunks(chunk) {
        pieces.push(piece);
    }
    let (whole, pieces) = (whole.finish(), pieces.finish());
    assert_eq!(whole, pieces, "chunking changed the facts");
    assert!(whole
        .usage
        .as_ref()
        .is_none_or(|u| u.len() <= MAX_USAGE_OBJECT_BYTES));
    for scalar in [&whole.size, &whole.quality, &whole.model, &whole.event_type] {
        assert!(scalar.as_ref().is_none_or(|s| s.len() <= MAX_SCALAR_BYTES));
    }
    if let Ok(serde_json::Value::Object(object)) = serde_json::from_slice(body) {
        assert!(whole.complete);
        let data = object
            .get("data")
            .and_then(|d| d.as_array())
            .map(|d| d.len() as u64);
        assert_eq!(whole.data_elements, data);
        if let Some(seconds) = object.get("duration").and_then(|d| d.as_f64()) {
            assert_eq!(whole.duration_ms, seconds_to_millis(seconds));
        }
        // A kept `size` is the decoded value; one too long to keep is
        // dropped, never cut.
        if let Some(size) = &whole.size {
            assert_eq!(
                object.get("size").and_then(|s| s.as_str()),
                Some(size.as_str())
            );
        }
    }

    let mut sse_whole = MediaSseScanner::new();
    sse_whole.push(body);
    let mut sse_pieces = MediaSseScanner::new();
    for piece in body.chunks(chunk) {
        sse_pieces.push(piece);
    }
    assert_eq!(
        sse_whole.facts(),
        sse_pieces.facts(),
        "chunking changed the stream facts"
    );
});
