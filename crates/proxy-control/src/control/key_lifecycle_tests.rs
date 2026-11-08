//! Virtual key expiry and rotation overlap, through the real `ControlPlane`
//! writes and the `VirtualKeyAuthenticator` that reads its published snapshot.

use std::sync::Arc;
use std::time::Duration;

use http::header::AUTHORIZATION;
use http::{HeaderMap, HeaderValue};

use super::{
    decode_json, encode_json, unix_now_secs, ControlPlane, EncodedKeyRow, ExpiryChange,
    InMemoryControlPlaneStore, PreviousDigest, RedbControlPlaneStore, SharedMemoryStore,
    StoreError, StoredKey, MAX_KEY_EXPIRES_AT, MAX_ROTATION_OVERLAP_SECS,
};
use crate::auth::{
    AuthError, AuthOutcome, Authenticator, HmacSecret, KeyId, KeyRecord, KeySet, TenantId,
    VirtualKeyAuthenticator,
};
use proxy_observability::chargeback::ChargebackTags;

const SECRET: &[u8] = b"key-lifecycle-secret";
const HOUR: u64 = 3600;

fn control_plane() -> ControlPlane {
    ControlPlane::new(
        Box::new(InMemoryControlPlaneStore::default()),
        HmacSecret::new(SECRET),
        KeySet::new(),
    )
    .expect("an empty store boots")
}

fn authenticator(cp: &ControlPlane) -> VirtualKeyAuthenticator {
    VirtualKeyAuthenticator::new(HmacSecret::new(SECRET), cp.handle())
}

fn bearer(plaintext: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {plaintext}")).unwrap(),
    );
    headers
}

/// The outcome as a short label, since `AuthOutcome` has no `Debug`.
fn outcome(auth: &VirtualKeyAuthenticator, plaintext: &str) -> String {
    match auth.authenticate(&bearer(plaintext)) {
        AuthOutcome::Authenticated(principal) => format!("ok:{}", principal.key_id.as_str()),
        AuthOutcome::Rejected(AuthError::RevokedKey) => "revoked".into(),
        AuthOutcome::Rejected(AuthError::UnknownKey) => "unknown".into(),
        AuthOutcome::Rejected(_) => "rejected:other".into(),
        AuthOutcome::NoCredential => "no-credential".into(),
    }
}

/// Sleeps until the wall clock reaches `deadline` (Unix seconds). A loaded
/// box only makes the wait longer, never the assertions after it wrong.
fn wait_until(deadline: u64) {
    let give_up = std::time::Instant::now() + Duration::from_secs(10);
    while unix_now_secs() < deadline {
        assert!(
            std::time::Instant::now() < give_up,
            "the clock did not reach {deadline} in 10 s (now {})",
            unix_now_secs()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Expiry is read from the clock on the worker at request time, so a key is
/// refused once it expires on the snapshot that admitted it: no republish,
/// poll or routing rollout is needed. The refusal is the revoked one.
#[test]
fn an_expired_key_is_refused_as_revoked_on_the_snapshot_that_admitted_it() {
    let cp = control_plane();
    let tenant = TenantId::new("tenant-a");
    // The mint refuses an expiry that is not in the future, so this key was
    // valid when the snapshot was published.
    let expires_at = unix_now_secs() + 1;
    let short = cp
        .mint_key_with(
            &tenant,
            &KeyId::new("short"),
            None,
            ExpiryChange::At(expires_at),
        )
        .unwrap();
    assert_eq!(short.expires_at, Some(expires_at));
    let lasting = cp
        .mint_key_with(
            &tenant,
            &KeyId::new("lasting"),
            None,
            ExpiryChange::At(unix_now_secs() + HOUR),
        )
        .unwrap();
    let auth = authenticator(&cp);
    let published = cp.handle().load_full();

    wait_until(expires_at);

    assert_eq!(outcome(&auth, &short.plaintext), "revoked");
    assert_eq!(outcome(&auth, &lasting.plaintext), "ok:lasting");
    assert!(
        Arc::ptr_eq(&published, &cp.handle().load_full()),
        "the refusal must come from the snapshot that admitted the key, not a republish"
    );
}

/// During the overlap both secrets authenticate as the same key, and the
/// listing shows one row with the overlap's end. A second rotation inside the
/// overlap is refused, since it would cut off the oldest secret unannounced.
#[test]
fn during_a_rotation_overlap_both_secrets_authenticate_as_one_key() {
    let cp = control_plane();
    let key = KeyId::new("k");
    let old = cp.mint_key(&TenantId::new("tenant-a"), &key).unwrap();
    let rotated = cp.rotate_key(&key, HOUR, ExpiryChange::Keep).unwrap();
    let auth = authenticator(&cp);

    assert_ne!(old.plaintext, rotated.plaintext);
    assert_eq!(outcome(&auth, &old.plaintext), "ok:k");
    assert_eq!(outcome(&auth, &rotated.plaintext), "ok:k");
    let listing = cp.list_keys();
    assert_eq!(listing.len(), 1, "one row per key: {listing:?}");
    assert_eq!(
        listing[0].previous_valid_until,
        rotated.previous_valid_until
    );

    assert!(matches!(
        cp.rotate_key(&key, HOUR, ExpiryChange::Keep),
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(outcome(&auth, &old.plaintext), "ok:k");
}

/// After the overlap's deadline only the new secret authenticates, on the
/// snapshot published by the rotation.
#[test]
fn after_the_overlap_deadline_only_the_new_secret_authenticates() {
    let cp = control_plane();
    let key = KeyId::new("k");
    let old = cp.mint_key(&TenantId::new("tenant-a"), &key).unwrap();
    let rotated = cp.rotate_key(&key, 1, ExpiryChange::Keep).unwrap();
    let auth = authenticator(&cp);
    let published = cp.handle().load_full();

    wait_until(
        rotated
            .previous_valid_until
            .expect("a rotation has a deadline"),
    );

    assert_eq!(outcome(&auth, &old.plaintext), "revoked");
    assert_eq!(outcome(&auth, &rotated.plaintext), "ok:k");
    assert!(Arc::ptr_eq(&published, &cp.handle().load_full()));
    assert_eq!(cp.list_keys()[0].previous_valid_until, None);
    // The closed overlap no longer blocks the next rotation.
    cp.rotate_key(&key, HOUR, ExpiryChange::Keep).unwrap();
}

/// A re-mint is the leaked-key path: it replaces the secret at once and ends
/// an open overlap, so neither earlier secret authenticates.
#[test]
fn a_re_mint_ends_a_rotation_overlap_at_once() {
    let cp = control_plane();
    let tenant = TenantId::new("tenant-a");
    let key = KeyId::new("k");
    let first = cp.mint_key(&tenant, &key).unwrap();
    let second = cp.rotate_key(&key, HOUR, ExpiryChange::Keep).unwrap();
    let third = cp.mint_key(&tenant, &key).unwrap();
    let auth = authenticator(&cp);

    assert_eq!(outcome(&auth, &first.plaintext), "unknown");
    assert_eq!(outcome(&auth, &second.plaintext), "unknown");
    assert_eq!(outcome(&auth, &third.plaintext), "ok:k");
    assert_eq!(cp.list_keys()[0].previous_valid_until, None);
}

/// A mint or rotation that does not mention expiry keeps it: dropping it
/// would make a key meant to expire permanent. Only an explicit clear
/// removes it, and an expiry that is not in the future is refused.
#[test]
fn a_re_mint_or_rotation_keeps_the_expiry_unless_told_otherwise() {
    let cp = control_plane();
    let tenant = TenantId::new("tenant-a");
    let key = KeyId::new("k");
    let at = unix_now_secs() + HOUR;
    cp.mint_key_with(&tenant, &key, None, ExpiryChange::At(at))
        .unwrap();

    assert_eq!(cp.mint_key(&tenant, &key).unwrap().expires_at, Some(at));
    assert_eq!(
        cp.rotate_key(&key, 60, ExpiryChange::Keep)
            .unwrap()
            .expires_at,
        Some(at)
    );
    assert_eq!(cp.list_keys()[0].expires_at, Some(at));
    let cleared = cp
        .mint_key_with(&tenant, &key, None, ExpiryChange::Clear)
        .unwrap();
    assert_eq!(cleared.expires_at, None);
    assert_eq!(cp.list_keys()[0].expires_at, None);

    for bad in [unix_now_secs(), MAX_KEY_EXPIRES_AT + 1] {
        assert!(
            matches!(
                cp.mint_key_with(&tenant, &key, None, ExpiryChange::At(bad)),
                Err(StoreError::InvalidInput(_))
            ),
            "expires_at {bad} must be refused"
        );
    }
    assert_eq!(
        cp.list_keys()[0].expires_at,
        None,
        "a refused mint writes nothing"
    );
}

/// A tag write rewrites the key row. It must carry the expiry and the open
/// overlap forward, or a tag change would make an expiring key permanent and
/// cut off the old secret mid-migration.
#[test]
fn a_tag_write_keeps_the_expiry_and_the_overlap() {
    let cp = control_plane();
    let tenant = TenantId::new("tenant-a");
    let key = KeyId::new("k");
    let at = unix_now_secs() + HOUR;
    let old = cp
        .mint_key_with(&tenant, &key, None, ExpiryChange::At(at))
        .unwrap();
    let rotated = cp.rotate_key(&key, HOUR, ExpiryChange::Keep).unwrap();

    let tags: ChargebackTags = [("team".to_string(), "infra".to_string())].into();
    cp.set_key_tags(&key, &tags).unwrap();

    let auth = authenticator(&cp);
    assert_eq!(outcome(&auth, &old.plaintext), "ok:k");
    assert_eq!(outcome(&auth, &rotated.plaintext), "ok:k");
    let listing = &cp.list_keys()[0];
    assert_eq!(listing.expires_at, Some(at));
    assert_eq!(listing.previous_valid_until, rotated.previous_valid_until);
    assert_eq!(*listing.tags, tags);
}

/// Two replicas on one store. A tag write on a replica that has not polled
/// since the other re-minted the key must not write the old secret back:
/// that would revive a secret replaced because it leaked.
#[test]
fn a_tag_write_does_not_restore_a_secret_another_replica_replaced() {
    let (store, _inner) = SharedMemoryStore::new();
    let boot = |store: SharedMemoryStore| {
        ControlPlane::new(Box::new(store), HmacSecret::new(SECRET), KeySet::new()).unwrap()
    };
    let replica_a = boot(store.handle());
    let tenant = TenantId::new("tenant-a");
    let key = KeyId::new("k");
    let leaked = replica_a.mint_key(&tenant, &key).unwrap();
    let replica_b = boot(store);
    let replacement = replica_a.mint_key(&tenant, &key).unwrap();

    let tags: ChargebackTags = [("team".to_string(), "infra".to_string())].into();
    assert!(matches!(
        replica_b.set_key_tags(&key, &tags),
        Err(StoreError::Conflict(_))
    ));
    replica_b.rebuild().unwrap();
    let auth = authenticator(&replica_b);
    assert_eq!(outcome(&auth, &leaked.plaintext), "unknown");
    assert_eq!(outcome(&auth, &replacement.plaintext), "ok:k");
}

/// When the key row cannot be read, a re-mint that does not mention expiry
/// keeps the expiry from this replica's snapshot rather than dropping it,
/// and says so in a warning, since it would miss an expiry set on another
/// replica since the last poll.
#[test]
fn a_re_mint_that_cannot_read_the_row_keeps_the_snapshot_expiry_and_warns() {
    let (store, _inner) = SharedMemoryStore::new();
    let hooks = Arc::clone(&store.hooks);
    let cp = ControlPlane::new(Box::new(store), HmacSecret::new(SECRET), KeySet::new()).unwrap();
    let tenant = TenantId::new("tenant-a");
    let key = KeyId::new("k");
    let at = unix_now_secs() + HOUR;
    cp.mint_key_with(&tenant, &key, None, ExpiryChange::At(at))
        .unwrap();

    let (capture, _guard) = super::log_capture::Capture::start();
    hooks
        .fail_loads
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let minted = cp.mint_key(&tenant, &key).unwrap();

    assert_eq!(minted.expires_at, Some(at));
    assert!(!minted.applied, "the reload after the write failed too");
    let warnings = capture.rendered_at_or_above(tracing::Level::WARN);
    assert!(
        warnings
            .iter()
            .any(|line| line.contains("could not read the key row")),
        "{warnings:?}"
    );
}

/// What a rotation refuses, each with the error the admin API maps to a
/// status: a key the configuration defines, an unknown or revoked key, an
/// overlap out of range, and an expiry in the past.
#[test]
fn rotation_refuses_keys_and_windows_it_cannot_serve() {
    let mut bootstrap = KeySet::new();
    bootstrap.insert(
        &HmacSecret::new(SECRET),
        "llmp_config-key",
        KeyRecord {
            key_id: KeyId::new("from-config"),
            tenant: TenantId::new("tenant-a"),
            revoked: false,
            tags: Default::default(),
            expires_at: None,
        },
    );
    let cp = ControlPlane::new(
        Box::new(InMemoryControlPlaneStore::default()),
        HmacSecret::new(SECRET),
        bootstrap,
    )
    .unwrap();
    let tenant = TenantId::new("tenant-a");
    cp.mint_key(&tenant, &KeyId::new("live")).unwrap();
    cp.mint_key(&tenant, &KeyId::new("gone")).unwrap();
    cp.revoke_key(&KeyId::new("gone")).unwrap();

    let cases: [(&str, u64, ExpiryChange, &str); 6] = [
        ("from-config", HOUR, ExpiryChange::Keep, "conflict"),
        ("missing", HOUR, ExpiryChange::Keep, "not-found"),
        ("gone", HOUR, ExpiryChange::Keep, "conflict"),
        ("live", 0, ExpiryChange::Keep, "invalid"),
        (
            "live",
            MAX_ROTATION_OVERLAP_SECS + 1,
            ExpiryChange::Keep,
            "invalid",
        ),
        ("live", HOUR, ExpiryChange::At(unix_now_secs()), "invalid"),
    ];
    for (key, overlap, expiry, expected) in cases {
        let got = match cp.rotate_key(&KeyId::new(key), overlap, expiry) {
            Err(StoreError::Conflict(_)) => "conflict",
            Err(StoreError::NotFound) => "not-found",
            Err(StoreError::InvalidInput(_)) => "invalid",
            Ok(_) => "ok",
            Err(_) => "other",
        };
        assert_eq!(got, expected, "rotate {key} overlap {overlap} {expiry:?}");
    }
    assert_eq!(
        cp.list_keys()
            .iter()
            .find(|k| k.key_id.as_str() == "live")
            .unwrap()
            .previous_valid_until,
        None,
        "a refused rotation writes nothing"
    );
}

/// A key that never expires and is not inside an overlap serializes exactly
/// as before expiry existed, so a store without such keys stays readable by a
/// build from before them. A row with an expiry or an overlap is stamped
/// version 4, which that build's reader (versions 1 to 3) refuses rather than
/// serving the key with no expiry.
#[test]
fn key_rows_are_stamped_version_4_only_with_an_expiry_or_an_overlap() {
    let mut key = StoredKey {
        key_id: KeyId::new("k"),
        digest: [7; 32],
        tenant: TenantId::new("t"),
        revoked: false,
        tags: ChargebackTags::new(),
        expires_at: None,
        previous: None,
    };
    let plain = String::from_utf8(encode_json(&EncodedKeyRow::from_stored(&key))).unwrap();
    assert_eq!(
        plain,
        r#"{"schema_version":2,"digest":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"tenant":"t","revoked":false}"#
    );
    key.tags = [("team".to_string(), "infra".to_string())].into();
    let tagged = String::from_utf8(encode_json(&EncodedKeyRow::from_stored(&key))).unwrap();
    assert!(tagged.contains(r#""schema_version":3"#), "{tagged}");

    #[derive(serde::Deserialize)]
    struct PreLifecycleRow {
        #[serde(deserialize_with = "read_pre_lifecycle_version")]
        #[allow(dead_code)]
        schema_version: u32,
    }
    fn read_pre_lifecycle_version<'de, D: serde::Deserializer<'de>>(
        de: D,
    ) -> Result<u32, D::Error> {
        let version = <u32 as serde::Deserialize>::deserialize(de)?;
        if matches!(version, 1..=3) {
            Ok(version)
        } else {
            Err(serde::de::Error::custom("unsupported"))
        }
    }

    let expiring = StoredKey {
        expires_at: Some(1_900_000_000),
        ..key.clone()
    };
    let rotated = StoredKey {
        previous: Some(PreviousDigest {
            digest: [9; 32],
            valid_until: 1_800_000_000,
        }),
        ..key.clone()
    };
    for row in [expiring, rotated] {
        let bytes = encode_json(&EncodedKeyRow::from_stored(&row));
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.contains(r#""schema_version":4"#), "{text}");
        assert!(decode_json::<PreLifecycleRow>(&bytes).is_err(), "{text}");
        let back = decode_json::<EncodedKeyRow>(&bytes)
            .unwrap()
            .into_stored(row.key_id.clone());
        assert_eq!(back.expires_at, row.expires_at);
        assert_eq!(back.previous, row.previous);
        assert_eq!(back.tags, row.tags);
    }
}

/// A row holding a previous digest without its deadline would accept the
/// old secret forever if read as is; it is read with no overlap instead.
#[test]
fn a_previous_digest_without_a_deadline_is_not_accepted() {
    let row = br#"{"schema_version":4,"digest":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"tenant":"t","revoked":false,"previous_digest":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2]}"#;
    let back = decode_json::<EncodedKeyRow>(row)
        .unwrap()
        .into_stored(KeyId::new("k"));
    assert_eq!(back.previous, None);
}

/// The redb store keeps the expiry and the overlap across a reopen and
/// through its revoke, which rewrites the row; a revoke refuses both secrets.
#[test]
fn redb_keeps_the_expiry_and_overlap_across_reopen_and_revoke() {
    let path = std::env::temp_dir().join(format!(
        "llm-proxy-key-lifecycle-{}-{}.redb",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let open = || {
        ControlPlane::new(
            Box::new(RedbControlPlaneStore::open(&path).unwrap()),
            HmacSecret::new(SECRET),
            KeySet::new(),
        )
        .unwrap()
    };
    let key = KeyId::new("k");
    let at = unix_now_secs() + HOUR;
    let (old, rotated) = {
        let cp = open();
        let old = cp
            .mint_key_with(&TenantId::new("tenant-a"), &key, None, ExpiryChange::At(at))
            .unwrap();
        (old, cp.rotate_key(&key, HOUR, ExpiryChange::Keep).unwrap())
    };
    let cp = open();
    let auth = authenticator(&cp);
    assert_eq!(outcome(&auth, &old.plaintext), "ok:k");
    assert_eq!(outcome(&auth, &rotated.plaintext), "ok:k");

    cp.revoke_key(&key).unwrap();
    let row = cp.store().load().unwrap().keys.remove(0);
    assert!(row.revoked);
    assert_eq!(row.expires_at, Some(at));
    assert_eq!(
        row.previous.map(|p| p.valid_until),
        rotated.previous_valid_until
    );
    assert_eq!(outcome(&auth, &old.plaintext), "revoked");
    assert_eq!(outcome(&auth, &rotated.plaintext), "revoked");
    let _ = std::fs::remove_file(&path);
}
