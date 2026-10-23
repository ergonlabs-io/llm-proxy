//! Virtual-key parsing and verification (`proxy-control` `auth.rs`): the
//! `Authorization` header every data-plane request presents, before any
//! other check runs.
//!
//! Input: a stored key's text after the `llmp_` prefix, then the presented
//! header value, split at the first 0xFF byte.
//!
//! Property, beyond "never panic": the outcome is exactly the one the header
//! text decides. A value is `Authenticated` only when it is `Bearer ` and the
//! stored key byte for byte, `RevokedKey` only for the revoked key, and
//! `NoCredential` (left to a later authenticator, such as JWT) exactly when it
//! is not shaped `Bearer llmp_...`. Anything else shaped like a virtual key
//! is `UnknownKey`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use proxy_control::auth::{
    AuthError, AuthOutcome, Authenticator, HmacSecret, KeyId, KeyRecord, KeySet, TenantId,
    VirtualKeyAuthenticator, BEARER_PREFIX, KEY_PREFIX,
};

const SECRET: &[u8] = b"fuzz-virtual-key-secret";
const REVOKED: &str = "llmp_revoked-key";

fuzz_target!(|data: &[u8]| {
    let Some(at) = data.iter().position(|&b| b == 0xFF) else {
        return;
    };
    let Ok(suffix) = std::str::from_utf8(&data[..at]) else {
        return;
    };
    let stored = format!("{KEY_PREFIX}{suffix}");
    if stored == REVOKED {
        return;
    }
    let Ok(value) = http::HeaderValue::from_bytes(&data[at + 1..]) else {
        return;
    };

    let secret = HmacSecret::new(SECRET);
    let mut keys = KeySet::new();
    keys.insert(
        &secret,
        &stored,
        KeyRecord {
            key_id: KeyId::new("key-1"),
            tenant: TenantId::new("tenant-a"),
            revoked: false,
            tags: Default::default(),
        },
    );
    keys.insert(
        &secret,
        REVOKED,
        KeyRecord {
            key_id: KeyId::new("key-revoked"),
            tenant: TenantId::new("tenant-a"),
            revoked: true,
            tags: Default::default(),
        },
    );
    let authenticator = VirtualKeyAuthenticator::from_static_keys(HmacSecret::new(SECRET), keys);
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::AUTHORIZATION, value.clone());
    let outcome = authenticator.authenticate(&headers);

    let presented = value
        .to_str()
        .ok()
        .and_then(|text| text.strip_prefix(BEARER_PREFIX))
        .filter(|key| key.starts_with(KEY_PREFIX));
    match (presented, outcome) {
        (None, AuthOutcome::NoCredential) => {}
        (Some(key), AuthOutcome::Authenticated(principal)) => {
            assert_eq!(key, stored, "a different key authenticated");
            assert_eq!(principal.key_id.as_str(), "key-1");
            assert_eq!(principal.tenant.as_str(), "tenant-a");
        }
        (Some(key), AuthOutcome::Rejected(AuthError::RevokedKey)) => assert_eq!(key, REVOKED),
        (Some(key), AuthOutcome::Rejected(AuthError::UnknownKey)) => {
            assert!(
                key != stored && key != REVOKED,
                "a stored key was not found"
            );
        }
        (presented, outcome) => {
            // `AuthOutcome` has no `Debug`: a `Principal` carries credentials.
            let outcome = match outcome {
                AuthOutcome::Authenticated(_) => "Authenticated".to_string(),
                AuthOutcome::Rejected(err) => format!("Rejected({err:?})"),
                AuthOutcome::NoCredential => "NoCredential".to_string(),
            };
            panic!("{presented:?} produced {outcome}")
        }
    }
});
