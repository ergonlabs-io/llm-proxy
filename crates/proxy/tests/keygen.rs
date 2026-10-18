//! Integration tests for `llm-proxy --mode keygen`.
//!
//! Test 4 (`printed_key_and_digest_authenticate_together_end_to_end`) is the
//! one that matters: it proves the generator (this command) and the
//! verifier (`proxy_filters::auth`, loaded from nothing but the printed
//! digest) actually agree, rather than merely re-deriving the digest with
//! the same function both share -- see `crates/proxy-control/src/auth.rs`'s
//! `digest_hex` doc for why that sharing can't drift on its own, and why
//! this test exists anyway to prove it end to end regardless.
//!
//! Rust note: `env!("CARGO_BIN_EXE_llm-proxy")` is filled in by cargo at
//! build time for integration tests -- see `tests/cli.rs`'s identical note.

use std::process::{Command, Output};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use http::header::AUTHORIZATION;
use http::{HeaderMap, HeaderValue};

use proxy_filters::auth::{
    digest_hex, AuthOutcome, Authenticator, HmacSecret, KeyId, KeyRecord, KeySet, TenantId,
    VirtualKeyAuthenticator,
};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");

/// Runs `llm-proxy --mode keygen --tenant <tenant> [--key-id <id>]`, with the
/// HMAC secret (if any) handed via `$LLMPROXY_AUTH_SECRET` rather than a
/// file -- keeps these tests self-contained, with no temp files to clean up.
///
/// `env_remove` runs unconditionally, before the optional `env`, so a secret
/// exported in the *ambient* shell running these tests can never leak in and
/// mask a missing-secret test case.
fn run_keygen(tenant: &str, key_id: Option<&str>, secret: Option<&str>) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(["--mode", "keygen", "--tenant", tenant]);
    if let Some(id) = key_id {
        cmd.args(["--key-id", id]);
    }
    cmd.env_remove("LLMPROXY_AUTH_SECRET");
    if let Some(secret) = secret {
        cmd.env("LLMPROXY_AUTH_SECRET", secret);
    }
    cmd.output().expect("failed to run llm-proxy")
}

/// Pulls the plaintext key (`llmp_...`) and the 64-hex digest out of the
/// command's documented stdout shape (see `keygen::run`'s doc). Panics with
/// the full stdout on a parse miss, so a failing test shows what it actually
/// saw instead of an opaque `None`/`unwrap`.
fn parse_output(stdout: &str) -> (String, String) {
    let key = stdout
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("llmp_"))
        .unwrap_or_else(|| panic!("no `llmp_`-prefixed key found in stdout:\n{stdout}"))
        .to_string();

    let digest = stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("digest:"))
        .unwrap_or_else(|| panic!("no `digest:` line found in stdout:\n{stdout}"))
        .trim()
        .to_string();

    (key, digest)
}

/// Reverses [`digest_hex`]'s hex formatting, independently of
/// `proxy_filters::auth`'s own (private) `decode_hex_digest` -- this is test
/// code turning a printed digest back into the bytes `KeySet::insert_digest`
/// wants, not a second production implementation to keep in sync.
fn decode_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "odd-length hex string: {hex:?}");
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let s = std::str::from_utf8(pair).expect("hex digest is ASCII");
            u8::from_str_radix(s, 16).unwrap_or_else(|e| panic!("bad hex byte {s:?}: {e}"))
        })
        .collect()
}

// --- 1: two invocations produce different keys ------------------------------

#[test]
fn two_invocations_produce_different_keys() {
    let out1 = run_keygen("acme", None, Some("test-secret"));
    let out2 = run_keygen("acme", None, Some("test-secret"));
    assert!(out1.status.success(), "{out1:?}");
    assert!(out2.status.success(), "{out2:?}");

    let (key1, _) = parse_output(&String::from_utf8_lossy(&out1.stdout));
    let (key2, _) = parse_output(&String::from_utf8_lossy(&out2.stdout));

    assert_ne!(
        key1, key2,
        "two invocations produced the SAME key -- the CSPRNG is not actually being read \
         (a constant would pass every other test in this file)"
    );
}

// --- 2: llmp_ prefix, decodes to exactly 32 bytes ---------------------------

#[test]
fn generated_key_has_llmp_prefix_and_decodes_to_32_bytes() {
    let out = run_keygen("acme", None, Some("test-secret"));
    assert!(out.status.success(), "{out:?}");
    let (key, _) = parse_output(&String::from_utf8_lossy(&out.stdout));

    let encoded = key
        .strip_prefix("llmp_")
        .unwrap_or_else(|| panic!("key {key:?} is missing the llmp_ prefix"));
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .unwrap_or_else(|e| panic!("key body {encoded:?} is not valid base64url: {e}"));
    assert_eq!(
        decoded.len(),
        32,
        "expected 32 bytes (256 bits) of entropy, got {}",
        decoded.len()
    );
}

// --- 3: printed digest == digest_hex(secret, printed key) -------------------

#[test]
fn printed_digest_matches_digest_hex_of_printed_key_under_given_secret() {
    let secret_bytes = b"test-secret-for-digest-check";
    let out = run_keygen(
        "acme",
        None,
        Some(std::str::from_utf8(secret_bytes).unwrap()),
    );
    assert!(out.status.success(), "{out:?}");
    let (key, digest) = parse_output(&String::from_utf8_lossy(&out.stdout));

    let secret = HmacSecret::new(secret_bytes);
    let expected = digest_hex(&secret, &key);
    assert_eq!(digest, expected);
}

// --- 4: THE end-to-end proof -------------------------------------------------

#[test]
fn printed_key_and_digest_authenticate_together_end_to_end() {
    let secret_bytes = b"end-to-end-secret";
    let out = run_keygen(
        "acme-corp",
        Some("alice-laptop"),
        Some(std::str::from_utf8(secret_bytes).unwrap()),
    );
    assert!(out.status.success(), "{out:?}");
    let (key, digest) = parse_output(&String::from_utf8_lossy(&out.stdout));

    // Build the KeySet from the PRINTED DIGEST alone, via `insert_digest` --
    // the same entry point `auth_filter::parse_config` uses for a real
    // `digest_hex` config field -- never by re-hashing `key` with `insert`.
    // A test that rehashed the plaintext here would only prove `digest_hex`
    // is deterministic, not that the generator and verifier agree.
    let mut keys = KeySet::new();
    keys.insert_digest(
        decode_hex(&digest),
        KeyRecord {
            key_id: KeyId::new("alice-laptop"),
            tenant: TenantId::new("acme-corp"),
            revoked: false,
        },
    );

    let authenticator =
        VirtualKeyAuthenticator::from_static_keys(HmacSecret::new(secret_bytes), keys);

    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {key}")).expect("valid header value"),
    );

    match authenticator.authenticate(&headers) {
        AuthOutcome::Authenticated(principal) => {
            assert_eq!(principal.tenant.as_str(), "acme-corp");
            assert_eq!(principal.key_id.as_str(), "alice-laptop");
        }
        AuthOutcome::Rejected(err) => panic!(
            "the printed key was REJECTED under the printed digest ({err:?}) -- the \
             generator and verifier have drifted apart"
        ),
        AuthOutcome::NoCredential => panic!(
            "the printed key was not even recognized as a credential -- check the llmp_ \
             prefix / Bearer scheme"
        ),
    }
}

// --- 5: wrong/absent secret is a clear error, not a panic -------------------

#[test]
fn missing_secret_is_a_clear_error_not_a_panic() {
    let out = run_keygen("acme", None, None);
    assert!(
        !out.status.success(),
        "expected a nonzero exit with no secret configured, got {out:?}"
    );
    assert_ne!(
        out.status.code(),
        Some(101),
        "exit code 101 is rustc's panic convention -- this must be a handled error, not an \
         unwrap/expect; stderr was {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("LLMPROXY_AUTH_SECRET") || stderr.contains("hmac-secret-file"),
        "expected a message naming the missing secret, got: {stderr}"
    );
}

#[test]
fn nonexistent_secret_file_is_a_clear_error_not_a_panic() {
    let path = std::env::temp_dir().join(format!(
        "llm-proxy-keygen-test-missing-secret-file-{}.txt",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path); // make sure it really doesn't exist

    let out = Command::new(BIN)
        .args([
            "--mode",
            "keygen",
            "--tenant",
            "acme",
            "--hmac-secret-file",
            path.to_str().unwrap(),
        ])
        .env_remove("LLMPROXY_AUTH_SECRET")
        .output()
        .expect("failed to run llm-proxy");

    assert!(
        !out.status.success(),
        "expected a nonzero exit for a nonexistent --hmac-secret-file, got {out:?}"
    );
    assert_ne!(
        out.status.code(),
        Some(101),
        "exit code 101 is rustc's panic convention -- this must be a handled error, not an \
         unwrap/expect; stderr was {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// --- 6: the regression guard -- serve with no config still errors -----------

#[test]
fn serve_mode_with_no_config_still_errors() {
    let out = Command::new(BIN)
        .args(["--mode", "serve"])
        .output()
        .expect("failed to run llm-proxy");
    assert!(
        !out.status.success(),
        "expected `--mode serve` with no config to fail now that the `input` ArgGroup is no \
         longer `required(true)` (loosened to let `--mode keygen` need neither flag) -- got \
         {out:?}"
    );
}

// --- 7: no output stream other than stdout carries the plaintext -----------

#[test]
fn plaintext_key_never_appears_on_stderr() {
    let out = run_keygen("acme", None, Some("test-secret"));
    assert!(out.status.success(), "{out:?}");
    let (key, _) = parse_output(&String::from_utf8_lossy(&out.stdout));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains(&key),
        "the plaintext key leaked into stderr: {stderr}"
    );
}
