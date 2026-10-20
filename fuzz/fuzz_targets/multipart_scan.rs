//! The multipart/form-data request scanner (`proxy-http` `multipart.rs`). It
//! reads client bytes of transcription, translation and image-edit uploads
//! to find the routing `model` and the shape facts a spend budget admits on,
//! and the router splices a mapped model into the range it reports.
//!
//! Input: byte 0 picks the mode, the rest is the input.
//! - Even: the rest is a raw body, delimited by the boundary `b`.
//! - Odd: the rest is split on 0xFF into (name, value) pairs, each pair's
//!   first byte picking a field name, and a well-formed form is built from
//!   them, so the fuzzer explores field contents rather than framing.
//!
//! Properties checked beyond "never panic":
//! - a kept value is within its bound, and the model range holds exactly the
//!   model value;
//! - splicing a new model at that range yields a form whose model is the new
//!   one and whose other facts are unchanged;
//! - on a built form, each field of interest sent once as valid UTF-8 within
//!   the bound is read back exactly, and a field sent twice is unproven.
#![no_main]

use libfuzzer_sys::fuzz_target;
use proxy_http::multipart::{replace_range, scan, Field, Outcome, MAX_FIELD_BYTES};

const NAMES: [&str; 6] = [
    "model",
    "response_format",
    "size",
    "quality",
    "stream",
    "file",
];

fn check(body: &[u8]) {
    let facts = scan(body, "b");
    for field in [
        &facts.model,
        &facts.response_format,
        &facts.size,
        &facts.quality,
        &facts.stream,
    ] {
        if let Field::Value(value) = field {
            assert!(value.len() <= MAX_FIELD_BYTES, "kept value over its bound");
        }
    }
    if facts.complete() {
        assert_eq!(facts.outcome, Outcome::Complete);
    }
    match (&facts.model, &facts.model_range) {
        (Field::Value(model), Some(range)) => {
            assert_eq!(
                &body[range.clone()],
                model.as_bytes(),
                "range is not the model"
            );
            let spliced = replace_range(body, range.clone(), "mapped-model").expect("splice");
            let again = scan(&spliced, "b");
            assert_eq!(again.model.value(), Some("mapped-model"));
            assert_eq!(again.response_format, facts.response_format);
            assert_eq!(again.size, facts.size);
            assert_eq!(again.outcome, facts.outcome);
        }
        (Field::Value(_), None) => panic!("a proven model has a range"),
        (_, Some(_)) => panic!("an unproven model has a range"),
        _ => {}
    }
}

fuzz_target!(|data: &[u8]| {
    let [mode, rest @ ..] = data else {
        return;
    };
    if mode % 2 == 0 {
        check(rest);
        return;
    }
    let mut body = Vec::new();
    let mut sent: Vec<(&str, &[u8])> = Vec::new();
    for pair in rest.split(|&b| b == 0xFF) {
        let [pick, value @ ..] = pair else {
            continue;
        };
        // A value holding the delimiter ends its part early: framing, not a
        // field fact, and the raw mode covers it.
        if value.windows(5).any(|w| w == b"\r\n--b") {
            return;
        }
        let name = NAMES[usize::from(*pick) % NAMES.len()];
        let filename = if name == "file" {
            "; filename=\"a\""
        } else {
            ""
        };
        body.extend_from_slice(
            format!("--b\r\nContent-Disposition: form-data; name=\"{name}\"{filename}\r\n\r\n")
                .as_bytes(),
        );
        body.extend_from_slice(value);
        body.extend_from_slice(b"\r\n");
        sent.push((name, value));
    }
    body.extend_from_slice(b"--b--\r\n");
    check(&body);
    let facts = scan(&body, "b");
    assert_eq!(
        facts.outcome,
        Outcome::Complete,
        "a built form was not followed"
    );
    for (name, field) in [
        ("model", &facts.model),
        ("response_format", &facts.response_format),
        ("size", &facts.size),
        ("quality", &facts.quality),
        ("stream", &facts.stream),
    ] {
        let values: Vec<&[u8]> = sent
            .iter()
            .filter(|(n, _)| *n == name)
            .map(|(_, v)| *v)
            .collect();
        let expected = match values.as_slice() {
            [] => Field::Absent,
            [one] if one.len() <= MAX_FIELD_BYTES => match std::str::from_utf8(one) {
                Ok(text) => Field::Value(text.to_string()),
                Err(_) => Field::Unproven,
            },
            _ => Field::Unproven,
        };
        assert_eq!(field, &expected, "{name}");
    }
});
