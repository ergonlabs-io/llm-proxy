use super::*;
use crate::server::fuzzing::Harness;
use crate::server::{parse_limits, parse_model_policy};
use hyper::Response;

const HMAC: &[u8] = b"object-bodies-hmac";

fn assert_refused<T>(result: Result<T, Response<Full<Bytes>>>, body: &str) {
    match result {
        Ok(_) => panic!("{body} parsed; a positional array is not a documented request shape"),
        Err(response) => assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body}"),
    }
}

/// Fuzz crash input (`admin_body`): a derived struct would read `["all"]` as
/// `{"access":"all"}` and grant every model.
#[test]
fn array_bodies_are_refused_not_read_positionally() {
    for body in [
        r#"["all"]"#,
        "[\"all\"]\n\n\n",
        r#"[{"only":["gpt-4o"]},["x"]]"#,
    ] {
        assert_refused(parse_model_policy(body.as_bytes()), body);
    }
    assert_refused(
        parse_limits(br#"[1,{"tokens_per_minute":5}]"#),
        "limits array",
    );
    // Nested structs too, not only the top level.
    assert_refused(
        parse_limits(br#"{"schema_version":1,"limits":[5,null,null]}"#),
        "nested limits array",
    );

    let harness = Harness::new(HMAC);
    assert_eq!(
        harness
            .mint_key(br#"{"tenant":"tenant-1","key_id":"key-1"}"#)
            .status,
        201
    );
    assert_eq!(harness.mint_key(br#"["tenant-2","key-2"]"#).status, 400);
    assert_eq!(harness.create_tenant(br#"["tenant-3"]"#).status, 400);
    let nested = harness.set_key_budget("key-1", br#"{"budget":["1.00","daily"]}"#);
    assert_eq!(nested.status, 400, "{:?}", nested.body);
}

#[test]
fn object_bodies_still_parse() {
    assert!(matches!(
        parse_model_policy(br#"{"access":"all"}"#),
        Ok(ModelAccess::All)
    ));
    assert!(parse_limits(br#"{"schema_version":1,"limits":null}"#)
        .expect("null clears")
        .is_none());
    assert!(
        parse_limits(br#"{"schema_version":1,"limits":{"requests_per_minute":6}}"#)
            .expect("an object parses")
            .is_some()
    );
    // Trailing bytes after the object stay a 400, as with `serde_json::from_slice`.
    assert_refused(
        parse_model_policy(br#"{"access":"all"} x"#),
        "trailing bytes",
    );

    let harness = Harness::new(HMAC);
    assert_eq!(
        harness
            .mint_key(br#"{"tenant":"tenant-1","key_id":"key-1"}"#)
            .status,
        201
    );
    for body in [
        r#"{"budget":{"max_usd":"1.00","period":"daily"}}"#,
        r#"{"budget":null}"#,
        "{}",
    ] {
        let answer = harness.set_key_budget("key-1", body.as_bytes());
        assert!(
            answer.status < 300,
            "{body}: {} {:?}",
            answer.status,
            answer.body
        );
    }
}
