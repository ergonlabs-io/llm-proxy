//! Admin API write bodies (`proxy-admin` `server.rs`): key minting, tenant
//! creation, budgets, limits, model policies and trace-export consent. The
//! admin token gates these, but a panic still takes the process down, and a
//! body that parses into something other than what the matching `GET`
//! renders is a policy the operator did not write.
//!
//! Input: byte 0 picks the endpoint; the rest is the path id and the body,
//! split at the first 0xFF byte (no 0xFF: the whole rest is the body).
//!
//! Properties checked beyond "never panic":
//! - no body makes a handler answer 5xx: a malformed body is the caller's
//!   fault (400), never a store failure;
//! - a minted key authenticates as exactly the tenant and key id the body
//!   named, and nothing but the exact key does;
//! - a budget's `max_usd` renders back to the same micro-dollars;
//! - a policy or limits body that parses, rendered as `GET /keys` shows it and
//!   sent again, parses to the same thing (`{"only": []}` stays deny-all).
#![no_main]

use libfuzzer_sys::fuzz_target;
use proxy_admin::server::fuzzing::{
    parse_budget, parse_limits, parse_model_policy, Answer, Harness,
};
use proxy_control::auth::{AuthOutcome, Authenticator, HmacSecret, VirtualKeyAuthenticator};
use proxy_control::spend::parse_micro_usd;

const HMAC_SECRET: &[u8] = b"fuzz-admin-hmac-secret";

fn assert_no_5xx(endpoint: &str, answer: &Answer) {
    assert!(
        answer.status < 500,
        "{endpoint} answered {} to a client body: {:?}",
        answer.status,
        String::from_utf8_lossy(&answer.body)
    );
}

fn authenticate(harness: &Harness, header: &str) -> AuthOutcome {
    let authenticator = VirtualKeyAuthenticator::new(
        HmacSecret::new(HMAC_SECRET),
        harness.control_plane().handle(),
    );
    let mut headers = http::HeaderMap::new();
    match http::HeaderValue::from_str(header) {
        Ok(value) => {
            headers.insert(http::header::AUTHORIZATION, value);
        }
        Err(_) => return AuthOutcome::NoCredential,
    }
    authenticator.authenticate(&headers)
}

fn check_mint(harness: &Harness, body: &[u8]) {
    let answer = harness.mint_key(body);
    assert_no_5xx("POST /keys", &answer);
    if answer.status != 201 {
        return;
    }
    let request: serde_json::Value = serde_json::from_slice(body).expect("accepted body is JSON");
    let response: serde_json::Value =
        serde_json::from_slice(&answer.body).expect("201 body is JSON");
    assert_eq!(response["tenant"], request["tenant"]);
    assert_eq!(response["key_id"], request["key_id"]);
    let key = response["key"].as_str().expect("201 carries the key");
    assert!(key.starts_with(proxy_control::auth::KEY_PREFIX));

    match authenticate(harness, &format!("Bearer {key}")) {
        AuthOutcome::Authenticated(principal) => {
            assert_eq!(Some(principal.tenant.as_str()), request["tenant"].as_str());
            assert_eq!(Some(principal.key_id.as_str()), request["key_id"].as_str());
        }
        _ => panic!("a freshly minted key does not authenticate"),
    }
    for near_miss in [
        format!("Bearer {key}x"),
        format!("Bearer {}", &key[..key.len() - 1]),
    ] {
        assert!(
            !matches!(
                authenticate(harness, &near_miss),
                AuthOutcome::Authenticated(_)
            ),
            "{near_miss:?} authenticated"
        );
    }
    let listing: serde_json::Value =
        serde_json::from_slice(&harness.list_keys().body).expect("GET /keys is JSON");
    assert!(
        listing["keys"]
            .as_array()
            .expect("keys array")
            .iter()
            .any(|k| k["key_id"] == request["key_id"]),
        "minted key missing from GET /keys"
    );
}

fn check_budget(harness: &Harness, key_id: &str, body: &[u8]) {
    let answer = harness.set_key_budget(key_id, body);
    assert_no_5xx("PUT /keys/{id}/budget", &answer);
    match parse_budget(body) {
        Ok(Some((micros, rendered))) => {
            let back = parse_micro_usd(&rendered).unwrap_or_else(|err| {
                panic!("rendered max_usd {rendered:?} does not parse: {err:?}")
            });
            assert_eq!(
                back.as_micros(),
                micros,
                "max_usd {rendered:?} changed value"
            );
        }
        Ok(None) => {}
        Err(status) => {
            assert_eq!(status, 400);
            assert_eq!(
                answer.status, 400,
                "the handler accepted a body the parser refused"
            );
        }
    }
}

fn check_policy(body: &[u8]) {
    let Ok(rendered) = parse_model_policy(body) else {
        return;
    };
    let resent = serde_json::to_vec(&rendered).expect("a Value serializes");
    let again = parse_model_policy(&resent)
        .unwrap_or_else(|status| panic!("rendered policy {rendered} refused with {status}"));
    assert_eq!(again, rendered, "policy changed on a round trip");
    let request: serde_json::Value = serde_json::from_slice(body).expect("accepted body is JSON");
    assert_eq!(
        request["access"] == "all",
        rendered["access"] == "all",
        "{request} rendered as {rendered}"
    );
}

fn check_limits(body: &[u8]) {
    let Ok(Some(rendered)) = parse_limits(body) else {
        return;
    };
    let resent =
        serde_json::to_vec(&serde_json::json!({ "limits": rendered })).expect("serializes");
    let again = parse_limits(&resent)
        .unwrap_or_else(|status| panic!("rendered limits {rendered} refused with {status}"));
    assert_eq!(again, Some(rendered), "limits changed on a round trip");
}

fuzz_target!(|data: &[u8]| {
    let [selector, rest @ ..] = data else {
        return;
    };
    let (id, body) = match rest.iter().position(|&b| b == 0xFF) {
        Some(at) => (
            String::from_utf8_lossy(&rest[..at]).into_owned(),
            &rest[at + 1..],
        ),
        None => ("key-1".to_string(), rest),
    };

    let harness = Harness::new(HMAC_SECRET);
    // A key and tenant that already exist, so writes reach the store.
    assert_eq!(
        harness
            .mint_key(br#"{"tenant":"tenant-1","key_id":"key-1"}"#)
            .status,
        201
    );

    match selector % 6 {
        0 => check_mint(&harness, body),
        1 => assert_no_5xx("POST /tenants", &harness.create_tenant(body)),
        2 => check_budget(&harness, &id, body),
        3 => assert_no_5xx(
            "PUT /tenants/{id}/trace_export",
            &harness.set_trace_export(&id, body),
        ),
        4 => check_policy(body),
        _ => check_limits(body),
    }
});
